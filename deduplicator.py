import sqlite3
import json
from datetime import datetime
from collections import defaultdict
import re

DB_FILE = 'sigma_rules.db'


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
            dt_str = row[3].split('.')[0]
            first_seen_dt = datetime.fromisoformat(dt_str)
        except (ValueError, TypeError) as e:
            print(f"Warnung: Datum für Regel {row[0]} ('{row[3]}') nicht lesbar: {e}. Nutze Fallback.")
            first_seen_dt = datetime.min

        rules_data.append({
            'id': row[0],
            'title': row[1],
            'detection_str': row[2],
            'first_seen_at': first_seen_dt,
            'rule_hash': row[4],
            'raw_rule': row[5],
        })
    return rules_data


def compare_detection_logic(detection_str1, detection_str2):
    try:
        return json.loads(detection_str1) == json.loads(detection_str2)
    except (json.JSONDecodeError, TypeError):
        return False


def deduplicate_rules():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    print("Lade Regeln aus der Datenbank...")
    all_rules = load_rules_from_db(conn)
    print(f"{len(all_rules)} Regeln geladen.")

    rules_by_norm_title = defaultdict(list)
    for rule in all_rules:
        rules_by_norm_title[normalize_title(rule['title'])].append(rule)

    ids_to_delete = set()
    updates_to_perform = []

    print("Analysiere Duplikate und Versionen...")
    for norm_title, rule_group in rules_by_norm_title.items():
        if len(rule_group) <= 1:
            original_rule = rule_group[0]
            stripped_title = original_rule['title'].strip()
            if original_rule['title'] != stripped_title:
                updates_to_perform.append((original_rule['id'], stripped_title))
            continue

        rule_group.sort(key=lambda r: r['first_seen_at'])

        # Pass 1: remove exact hash duplicates, keep oldest
        unique_by_hash = []
        seen_hashes = set()
        for rule in rule_group:
            if rule['id'] in ids_to_delete:
                continue
            if rule['rule_hash'] in seen_hashes:
                print(f"  Exaktes Duplikat '{norm_title}': lösche {rule['id']}")
                ids_to_delete.add(rule['id'])
            else:
                unique_by_hash.append(rule)
                seen_hashes.add(rule['rule_hash'])

        if not unique_by_hash:
            continue

        primary_rule = unique_by_hash[0]
        stripped_primary_title = primary_rule['title'].strip()
        if primary_rule['title'] != stripped_primary_title:
            updates_to_perform.append((primary_rule['id'], stripped_primary_title))

        version_counter = 2

        # Pass 2: same detection logic → delete; different → rename as vN
        for variant in unique_by_hash[1:]:
            if variant['id'] in ids_to_delete:
                continue
            if compare_detection_logic(variant['detection_str'], primary_rule['detection_str']):
                print(f"  Selbe Detektion '{norm_title}': lösche {variant['id']}")
                ids_to_delete.add(variant['id'])
            else:
                new_title = f"{stripped_primary_title} v{version_counter}"
                print(f"  Neue Version '{norm_title}': {variant['id']} → '{new_title}'")
                updates_to_perform.append((variant['id'], new_title))
                version_counter += 1

    if not ids_to_delete and not updates_to_perform:
        print("Keine Duplikate gefunden.")
        conn.close()
        return

    print(f"\nGeplante Aktionen:")
    print(f"  Löschen:    {len(ids_to_delete)} Regeln")
    print(f"  Umbenennen: {len(updates_to_perform)} Regeln")

    confirm = input("\nÄnderungen durchführen? (ja/nein): ").strip().lower()
    if confirm == 'ja':
        cursor = conn.cursor()
        try:
            for rule_id in ids_to_delete:
                cursor.execute("DELETE FROM sigma_rules WHERE id = ?", (rule_id,))
            for rule_id, new_title in updates_to_perform:
                cursor.execute("UPDATE sigma_rules SET title = ? WHERE id = ?", (new_title, rule_id))
            conn.commit()
            print("Fertig.")
        except sqlite3.Error as e:
            conn.rollback()
            print(f"Fehler: {e}")
        finally:
            conn.close()
    else:
        print("Keine Änderungen durchgeführt.")
        conn.close()


if __name__ == '__main__':
    deduplicate_rules()
