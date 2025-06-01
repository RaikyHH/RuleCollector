import sqlite3
import json
import hashlib
from datetime import datetime
from collections import defaultdict
import re

DB_FILE = 'sigma_rules.db' # Dieselbe DB-Datei wie beim Collector

def normalize_title(title):
    if not title:
        return ""
    return title.strip().lower()

def load_rules_from_db(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, detection, first_seen_at, rule_hash, raw_rule FROM sigma_rules")
    rules_data = []
    for row in cursor.fetchall():
        try:
            # Konvertiere first_seen_at zu datetime für Sortierung
            # Behandlung verschiedener Timestamp-Formate, falls nötig. ISO-Format wird angenommen.
            # Ignoriere Mikrosekunden für einfacheres Parsen, falls vorhanden.
            dt_str = row[3].split('.')[0]
            first_seen_dt = datetime.fromisoformat(dt_str)
        except (ValueError, TypeError) as e:
            print(f"Warning: Could not parse datetime for rule {row[0]} ('{row[3]}'): {e}. Using epoch as fallback.")
            first_seen_dt = datetime.min # Fallback, damit es sortierbar bleibt

        rules_data.append({
            'id': row[0],
            'title': row[1],
            'detection_str': row[2], # JSON-String der Detektion
            'first_seen_at': first_seen_dt,
            'rule_hash': row[4],
            'raw_rule': row[5] # Für Debugging oder komplexere Vergleiche ggf. nützlich
        })
    return rules_data

def compare_detection_logic(detection_str1, detection_str2):
    try:
        dict1 = json.loads(detection_str1)
        dict2 = json.loads(detection_str2)
        return dict1 == dict2
    except (json.JSONDecodeError, TypeError):
        # Wenn eine Detektion nicht valides JSON ist, können sie nicht gleich sein
        # oder man behandelt es als Fehler. Für den Vergleich: ungleich.
        return False

def deduplicate_rules():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row # Zugriff auf Spalten per Name
    
    print("Lade Regeln aus der Datenbank...")
    all_rules = load_rules_from_db(conn)
    print(f"{len(all_rules)} Regeln geladen.")

    rules_by_norm_title = defaultdict(list)
    for rule in all_rules:
        rules_by_norm_title[normalize_title(rule['title'])].append(rule)

    ids_to_delete = set()
    updates_to_perform = [] # Liste von Tupeln (id, new_title)

    print("Analysiere Regeln auf Duplikate und Versionen...")
    for norm_title, rule_group in rules_by_norm_title.items():
        if len(rule_group) <= 1:
            # Ggf. Titel normalisieren, falls Original Leerzeichen/Groß-Kleinschreibung hatte
            original_rule = rule_group[0]
            stripped_title = original_rule['title'].strip()
            if original_rule['title'] != stripped_title:
                 updates_to_perform.append((original_rule['id'], stripped_title))
            continue

        # Sortiere Regeln innerhalb der Gruppe nach 'first_seen_at' (älteste zuerst)
        rule_group.sort(key=lambda r: r['first_seen_at'])

        # Schritt 1: Exakte Duplikate (gleicher rule_hash) entfernen
        unique_by_hash_rules = []
        processed_hashes_in_group = set()
        for rule in rule_group:
            if rule['id'] in ids_to_delete: # Bereits durch andere Logik markiert
                continue
            if rule['rule_hash'] in processed_hashes_in_group:
                print(f"  Exaktes Duplikat (gleicher Hash '{rule['rule_hash']}') für Titel '{norm_title}': Lösche ID {rule['id']} ('{rule['title']}'). Behalte ältere Version.")
                ids_to_delete.add(rule['id'])
            else:
                unique_by_hash_rules.append(rule)
                processed_hashes_in_group.add(rule['rule_hash'])
        
        if not unique_by_hash_rules: # Alle waren exakte Duplikate voneinander
            continue

        # Jetzt haben wir unique_by_hash_rules, sortiert nach first_seen_at.
        # Die erste Regel in dieser Liste ist die primäre für diesen Titel.
        primary_rule = unique_by_hash_rules[0]
        
        # Titel der primären Regel ggf. normalisieren (Leerzeichen entfernen)
        stripped_primary_title = primary_rule['title'].strip()
        if primary_rule['title'] != stripped_primary_title:
            # Wenn der norm_title (lowercase) vom stripped_primary_title (original case) abweicht,
            # dann ist der stripped_primary_title derjenige, der für Versionierung als Basis dient.
            # Wenn der Originaltitel der primären Regel z.B. " My Rule " war, wird er zu "My Rule".
            # Wenn die primäre Regel selbst umbenannt werden muss (wegen stripping), füge es hinzu.
            # Dies ist wichtig, falls die primäre Regel die einzige ist und nur Leerzeichen hatte.
            # Wenn sie die erste einer Gruppe ist, wird ihr Titel die Basis für vX.
            updates_to_perform.append((primary_rule['id'], stripped_primary_title))
        
        version_counter = 2 # Beginnt mit v2 für die nächste abweichende Regel

        # Schritt 2: Vergleiche Detektionslogik der verbleibenden (Hash-eindeutigen) Regeln
        for i in range(1, len(unique_by_hash_rules)):
            current_variant_rule = unique_by_hash_rules[i]
            if current_variant_rule['id'] in ids_to_delete: # Kann passieren, falls Logik komplexer wird
                continue

            if compare_detection_logic(current_variant_rule['detection_str'], primary_rule['detection_str']):
                # Gleiche Detektionslogik wie die primäre Regel. Löschen.
                print(f"  Duplikat (gleiche Detektion) für Titel '{norm_title}': Lösche ID {current_variant_rule['id']} ('{current_variant_rule['title']}'). Primär: ID {primary_rule['id']}.")
                ids_to_delete.add(current_variant_rule['id'])
            else:
                # Unterschiedliche Detektionslogik. Umbenennen.
                # Basis für den neuen Titel ist der (ggf. gestrippte) Titel der primären Regel.
                new_title = f"{stripped_primary_title} v{version_counter}"
                print(f"  Neue Version für Titel '{norm_title}': ID {current_variant_rule['id']} ('{current_variant_rule['title']}') wird zu '{new_title}'.")
                updates_to_perform.append((current_variant_rule['id'], new_title))
                version_counter += 1
    
    # Änderungen in der Datenbank durchführen
    if not ids_to_delete and not updates_to_perform:
        print("Keine Duplikate oder notwendigen Titelanpassungen gefunden.")
        conn.close()
        return

    print(f"\nDurchzuführende Aktionen:")
    print(f"  Zu löschende Regel-IDs ({len(ids_to_delete)}): {ids_to_delete if ids_to_delete else 'Keine'}")
    if updates_to_perform:
        print(f"  Umzubenennende Regeln ({len(updates_to_perform)}):")
        for old_id, new_title_val in updates_to_perform:
            print(f"    ID {old_id} -> neuer Titel '{new_title_val}'")
    else:
        print("  Umzubenennende Regeln: Keine")

    confirm = input("\Möchten Sie diese Änderungen in der Datenbank durchführen? (ja/nein): ").lower()
    if confirm == 'ja':
        cursor = conn.cursor()
        try:
            for rule_id_to_delete in ids_to_delete:
                cursor.execute("DELETE FROM sigma_rules WHERE id = ?", (rule_id_to_delete,))
            
            for rule_id_to_update, new_title_val in updates_to_perform:
                cursor.execute("UPDATE sigma_rules SET title = ? WHERE id = ?", (new_title_val, rule_id_to_update))
            
            conn.commit()
            print("Änderungen erfolgreich durchgeführt.")
        except sqlite3.Error as e:
            conn.rollback()
            print(f"Fehler bei der Datenbankaktualisierung: {e}")
        finally:
            conn.close()
    else:
        print("Keine Änderungen durchgeführt.")
        conn.close()

if __name__ == '__main__':
    deduplicate_rules()