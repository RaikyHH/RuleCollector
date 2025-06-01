import requests
import yaml
import json
import re
import sqlite3
import hashlib
from datetime import datetime
import time
import os
import uuid

# --- Rich Imports ---
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, TaskID
from rich.text import Text
from rich.table import Table

# --- Global Config ---
CONFIG_FILE = 'config.json'
DB_FILE = 'sigma_rules.db'
RULES_DIR = 'sigma_rules_files'
REQUEST_TIMEOUT = 30
USER_AGENT = "SigmaRuleCollector/1.0"

# --- Rich Console ---
console = Console(width=150)

def get_elapsed_time_str(start_time_seconds: float) -> str:
    """Konvertiert verstrichene Sekunden seit start_time_seconds in HH:MM:SS."""
    elapsed_total_seconds = int(time.time() - start_time_seconds)
    hours, remainder = divmod(elapsed_total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

def normalize_title(title):
    if not title: return ""
    return title.strip().lower()

def init_db(overall_start_time: float):
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sigma_rules (
            id TEXT PRIMARY KEY, title TEXT, status TEXT, description TEXT, author TEXT,
            "references" TEXT, logsource_category TEXT, logsource_product TEXT, detection TEXT,
            falsepositives TEXT, level TEXT, tags TEXT, raw_rule TEXT, source_name TEXT,
            source_url TEXT, first_seen_at TIMESTAMP, last_updated_at TIMESTAMP, rule_hash TEXT
        )''')
        conn.commit()
        console.print(f"[{get_elapsed_time_str(overall_start_time)}] Datenbank initialisiert.", style="dim")
    except Exception as e:
        console.print(f"[{get_elapsed_time_str(overall_start_time)}] [bold red]Kritischer Fehler bei DB-Initialisierung: {e}. Skript wird beendet.[/bold red]")
        raise
    finally:
        if conn:
            conn.close()

def get_status_style(status_text: str) -> str:
    """Gibt einen Rich-Style basierend auf dem Status-Text zurück."""
    if "[DB TS ✅]" in status_text: # Spezifischer Fall für das Häkchen
        return "cyan"
    if "OK" in status_text or "Neu Hinzugefügt" in status_text or "Als Version" in status_text :
        return "green"
    if "Aktualisiert" in status_text : # Allgemeiner Fall, falls [DB TS ✅] nicht greift
        return "cyan"
    if "Fehler" in status_text: # Fehler explizit rot
        return "red"
    if "Defekte Regel" in status_text: # Spezifischer für orange
        return "orange_red1"
    if "Übersprungen (kein Titel)" in status_text:
        return "yellow"
    if "Unverändert" in status_text or "N/A" in status_text or "Übersprungen" in status_text: # Allgemeines Überspringen
        return "dim"
    return "default"


def store_rule(parsed_rule_data, raw_rule_content, source_name, source_url, live_status: dict, overall_start_time: float):
    conn = None
    rule_processed_for_stats = True
    new_rule_title_from_file = parsed_rule_data.get('title', 'Unbenannte Regel').strip()

    db_status_text = "[DB Unverändert]"
    file_status_text = "[Datei N/A]"
    filename_for_saving = "ErrorInFilenameGeneration.yml"

    # Längen für die Log-Anzeige
    LOG_RULE_TITLE_LEN = 65
    LOG_SOURCE_NAME_LEN = 22
    LOG_FILENAME_DISPLAY_LEN = 35


    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        current_time = datetime.now()

        if not os.path.exists(RULES_DIR):
            try: os.makedirs(RULES_DIR)
            except OSError: pass

        new_rule_id_from_file = parsed_rule_data.get('id')
        if new_rule_id_from_file is not None: new_rule_id_from_file = str(new_rule_id_from_file)

        new_rule_detection_dict = parsed_rule_data.get('detection', {})
        new_rule_hash = hashlib.sha256(raw_rule_content.encode('utf-8')).hexdigest()

        if not new_rule_id_from_file:
            title_slug = re.sub(r'\W+', '_', new_rule_title_from_file.lower() if new_rule_title_from_file else 'untitled')
            new_rule_id_from_file = f"gen_{title_slug[:50]}_{new_rule_hash[:8]}"

        if not new_rule_title_from_file:
            db_status_text = "[Übersprungen (kein Titel)]"
            file_status_text = "[Datei Übersprungen]" # Sync mit DB-Status
            log_line_str = (
                f"[dim white][{get_elapsed_time_str(overall_start_time)}][/dim white] "
                f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' " # Titel auch hier anzeigen, auch wenn leer
                f"([italic]{source_name[:LOG_SOURCE_NAME_LEN]}[/italic]): "
                f"[{get_status_style(db_status_text)}]{db_status_text}[/]"
            )
            console.print(Text.from_markup(log_line_str), overflow="ellipsis")
            live_status["session_rules_skipped_no_title"] = live_status.get("session_rules_skipped_no_title", 0) + 1
            rule_processed_for_stats = False
            return

        cleaned_title_for_filename = re.sub(r'[^\w\._-]+', '_', new_rule_title_from_file)
        filename_for_saving = f"{cleaned_title_for_filename[:100]}_{new_rule_hash[:8]}.yml"

        try:
            if not os.path.exists(RULES_DIR): file_status_text = "[Datei Fehler (Ordner fehlt)]"
            else:
                filepath = os.path.join(RULES_DIR, filename_for_saving)
                with open(filepath, 'w', encoding='utf-8') as f_rule: f_rule.write(raw_rule_content)
                file_status_text = f"[Datei: ✅]"
        except Exception as e_file: file_status_text = f"[Datei Fehler: {str(e_file)[:75]}]"

        cursor.execute("SELECT * FROM sigma_rules WHERE id = ?", (new_rule_id_from_file,))
        db_rule_by_id = cursor.fetchone()
        original_db_status_for_style = "" # Für get_status_style

        if db_rule_by_id:
            if db_rule_by_id['rule_hash'] == new_rule_hash:
                cursor.execute("UPDATE sigma_rules SET last_updated_at = ?, source_name = ?, source_url = ? WHERE id = ?", (current_time, source_name, source_url, new_rule_id_from_file))
                original_db_status_for_style = "[DB Zeitstempel Aktualisiert]" # Für Style-Logik
                db_status_text = "[DB: ✅]"
                live_status["session_rules_updated_ts"] = live_status.get("session_rules_updated_ts", 0) + 1
            else:
                logsource = parsed_rule_data.get('logsource', {}); detection = parsed_rule_data.get('detection', {})
                cursor.execute("UPDATE sigma_rules SET title=?, status=?, description=?, author=?, \"references\"=?, logsource_category=?, logsource_product=?, detection=?, falsepositives=?, level=?, tags=?, raw_rule=?, source_name=?, source_url=?, last_updated_at=?, rule_hash=? WHERE id=?",
                               (new_rule_title_from_file, parsed_rule_data.get('status'), parsed_rule_data.get('description'), parsed_rule_data.get('author'), json.dumps(parsed_rule_data.get('references', [])), logsource.get('category'), logsource.get('product'), json.dumps(detection), json.dumps(parsed_rule_data.get('falsepositives', [])), parsed_rule_data.get('level'), json.dumps(parsed_rule_data.get('tags', [])), raw_rule_content, source_name, source_url, current_time, new_rule_hash, new_rule_id_from_file))
                original_db_status_for_style = db_status_text = "[DB Inhalt Aktualisiert]"
                live_status["session_rules_updated_content"] = live_status.get("session_rules_updated_content", 0) + 1
        else:
            base_title_new = normalize_title(re.sub(r"\s*v\d+(\.\d+)*$", "", new_rule_title_from_file, flags=re.IGNORECASE).strip())
            cursor.execute("SELECT id, title, rule_hash, detection, first_seen_at FROM sigma_rules")
            all_db_rules = cursor.fetchall()
            title_family_rules_db = []
            for row in all_db_rules:
                db_title_stripped = normalize_title(re.sub(r"\s*v\d+(\.\d+)*$", "", row['title'], flags=re.IGNORECASE).strip())
                if db_title_stripped == base_title_new:
                    try: dt_str = row['first_seen_at'].split('.')[0]; first_seen_dt = datetime.fromisoformat(dt_str)
                    except: first_seen_dt = datetime.min
                    title_family_rules_db.append({**dict(row), 'first_seen_at_dt': first_seen_dt})

            if not title_family_rules_db:
                logsource = parsed_rule_data.get('logsource', {}); detection = parsed_rule_data.get('detection', {})
                cursor.execute("INSERT INTO sigma_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (new_rule_id_from_file, new_rule_title_from_file, parsed_rule_data.get('status'), parsed_rule_data.get('description'), parsed_rule_data.get('author'), json.dumps(parsed_rule_data.get('references', [])), logsource.get('category'), logsource.get('product'), json.dumps(detection), json.dumps(parsed_rule_data.get('falsepositives', [])), parsed_rule_data.get('level'), json.dumps(parsed_rule_data.get('tags', [])), raw_rule_content, source_name, source_url, current_time, current_time, new_rule_hash))
                original_db_status_for_style = db_status_text = "[DB Neu Hinzugefügt]"
                live_status["session_rules_added_new"] = live_status.get("session_rules_added_new", 0) + 1
            else:
                title_family_rules_db.sort(key=lambda r: r['first_seen_at_dt'])
                primary_rule = title_family_rules_db[0]
                hash_match_in_family = any(r['rule_hash'] == new_rule_hash for r in title_family_rules_db)
                if hash_match_in_family:
                    matched_rule_id_obj = next(r['id'] for r in title_family_rules_db if r['rule_hash'] == new_rule_hash)
                    cursor.execute("UPDATE sigma_rules SET last_updated_at=?, source_name=?, source_url=? WHERE id=?", (current_time, source_name, source_url, str(matched_rule_id_obj)))
                    original_db_status_for_style = "[DB Zeitstempel Aktualisiert (Hash-Match in Familie)]"
                    db_status_text = "[DB: ✅]"
                    live_status["session_rules_updated_ts"] = live_status.get("session_rules_updated_ts", 0) + 1
                else:
                    try: primary_detection_dict = json.loads(primary_rule['detection'])
                    except (json.JSONDecodeError, TypeError): primary_detection_dict = {}
                    if new_rule_detection_dict == primary_detection_dict:
                        cursor.execute("UPDATE sigma_rules SET last_updated_at=?, source_name=?, source_url=? WHERE id=?", (current_time, source_name, source_url, str(primary_rule['id'])))
                        original_db_status_for_style = "[DB Zeitstempel Aktualisiert (Detection-Match in Familie)]"
                        db_status_text = "[DB: ✅]"
                        live_status["session_rules_updated_ts"] = live_status.get("session_rules_updated_ts", 0) + 1
                    else:
                        base_title_versioning = re.sub(r"\s*v\d+(\.\d+)*$", "", primary_rule['title'], flags=re.IGNORECASE).strip()
                        max_v = 0
                        for r_v in title_family_rules_db:
                            m = re.match(rf"^{re.escape(base_title_versioning)}\s*v(\d+)", r_v['title'], re.IGNORECASE)
                            if m: max_v = max(max_v, int(m.group(1)))
                        if max_v == 0 and normalize_title(primary_rule['title']) == normalize_title(base_title_versioning): max_v = 1
                        versioned_title = f"{base_title_versioning} v{max_v + 1}"
                        logsource = parsed_rule_data.get('logsource', {}); detection = parsed_rule_data.get('detection', {})
                        cursor.execute("INSERT INTO sigma_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (new_rule_id_from_file, versioned_title, parsed_rule_data.get('status'), parsed_rule_data.get('description'), parsed_rule_data.get('author'), json.dumps(parsed_rule_data.get('references', [])), logsource.get('category'), logsource.get('product'), json.dumps(detection), json.dumps(parsed_rule_data.get('falsepositives', [])), parsed_rule_data.get('level'), json.dumps(parsed_rule_data.get('tags', [])), raw_rule_content, source_name, source_url, current_time, current_time, new_rule_hash))
                        original_db_status_for_style = db_status_text = f"[DB Als Version '{versioned_title}' Hinzugefügt]"
                        live_status["session_rules_added_version"] = live_status.get("session_rules_added_version", 0) + 1
        
        if not original_db_status_for_style: # Wenn kein spezifischer DB-Status gesetzt wurde (Default war Unverändert)
            original_db_status_for_style = db_status_text # Sollte "[DB Unverändert]" sein
        
        conn.commit()

        log_display_filename = filename_for_saving
        if len(filename_for_saving) > LOG_FILENAME_DISPLAY_LEN:
            log_display_filename = filename_for_saving[:LOG_FILENAME_DISPLAY_LEN-3] + "..."
        
        current_file_status_for_log = file_status_text
        if file_status_text.startswith("[Datei: ✅"):
             current_file_status_for_log = f"[Datei: ✅]"

        log_line_str = (
            f"[dim white][{get_elapsed_time_str(overall_start_time)}][/dim white] "
            f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' "
            f"([italic]{source_name[:LOG_SOURCE_NAME_LEN]}[/italic]): "
            f"[{get_status_style(original_db_status_for_style)}]{db_status_text}[/] - "
            f"[{get_status_style(file_status_text)}]{current_file_status_for_log}[/]"
        )
        console.print(Text.from_markup(log_line_str), overflow="ellipsis")

    except sqlite3.Error as e_sql:
        db_status_text = f"[DB-Fehler: {str(e_sql)[:100]}]"
        log_line_str = (
            f"[dim white][{get_elapsed_time_str(overall_start_time)}][/dim white] "
            f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' "
            f"([italic]{source_name[:LOG_SOURCE_NAME_LEN]}[/italic]): "
            f"[{get_status_style(db_status_text)}]{db_status_text}[/] - " # original_db_status_for_style nicht relevant bei Fehler
            f"[{get_status_style(file_status_text)}]{file_status_text}[/]"
        )
        console.print(Text.from_markup(log_line_str), overflow="ellipsis")
        rule_processed_for_stats = False
    except Exception as e_gen:
        db_status_text = f"[Allg. Fehler: {str(e_gen)[:100]}]"
        log_line_str = (
            f"[dim white][{get_elapsed_time_str(overall_start_time)}][/dim white] "
            f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' "
            f"([italic]{source_name[:LOG_SOURCE_NAME_LEN]}[/italic]): "
            f"[{get_status_style(db_status_text)}]{db_status_text}[/] - "
            f"[{get_status_style(file_status_text)}]{file_status_text}[/]"
        )
        console.print(Text.from_markup(log_line_str), overflow="ellipsis")
        rule_processed_for_stats = False
    finally:
        if conn: conn.close()
        if rule_processed_for_stats:
             live_status["session_rules_processed"] = live_status.get("session_rules_processed", 0) + 1
        elif not (db_status_text == "[Übersprungen (kein Titel)]"):
             live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
    time.sleep(0.005)


def fetch_url_content(url, headers, source_name: str, overall_start_time: float):
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        console.print(f"[{get_elapsed_time_str(overall_start_time)}]   [red]Netzwerkfehler[/red] für {source_name} (URL: ...{url[-90:]}): {str(e)[:150]}")
        return None
    except Exception as e_gen:
        console.print(f"[{get_elapsed_time_str(overall_start_time)}]   [red]Unerwarteter Fehler beim Download[/red] für {source_name} (URL: ...{url[-90:]}): {str(e_gen)[:150]}")
        return None

def fetch_and_process_github_directory(api_dir_url, source_config_name, base_request_headers, live_status: dict, overall_start_time: float):
    directory_content_text = fetch_url_content(api_dir_url, base_request_headers, source_config_name, overall_start_time)
    if not directory_content_text: return

    try:
        items = json.loads(directory_content_text)
        if not isinstance(items, list):
            if isinstance(items, dict) and items.get('type') == 'file': items = [items]
            elif isinstance(items, dict) and 'message' in items:
                console.print(f"[{get_elapsed_time_str(overall_start_time)}]   [red]GitHub API Fehler[/red] in {source_config_name} (...{api_dir_url[-75:]}): {items.get('message')[:150]}")
                return
            else:
                console.print(f"[{get_elapsed_time_str(overall_start_time)}]   [red]Unerwartete GitHub API Antwort[/red] für {source_config_name} (...{api_dir_url[-75:]})")
                return

        for item in items:
            item_path = item.get('path', item.get('name', 'unbekanntes_item'))
            is_yaml_file = item.get('type') == 'file' and item.get('name', '').endswith(('.yml', '.yaml'))

            if is_yaml_file:
                file_download_url = item.get('download_url')
                if not file_download_url:
                    log_line_str = (f"[{get_elapsed_time_str(overall_start_time)}]   "
                                    f"[yellow]Keine Download-URL[/yellow] für '{item_path[:90]}' in {source_config_name}.")
                    console.print(Text.from_markup(log_line_str), overflow="ellipsis")
                    live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                    live_status["session_rules_processed"] += 1
                    continue

                file_content = fetch_url_content(file_download_url, base_request_headers, source_config_name, overall_start_time)
                if file_content:
                    try:
                        cleaned_content = file_content.replace('\xa0', ' ').replace('\ufeff', '')
                        rule_data = yaml.safe_load(cleaned_content)
                        if isinstance(rule_data, dict) and rule_data.get('title'):
                            store_rule(rule_data, cleaned_content, source_config_name, file_download_url, live_status, overall_start_time)
                        else:
                            def_msg = "[Defekte Regel]"
                            log_line_str = (f"[{get_elapsed_time_str(overall_start_time)}]   "
                                            f"[{get_status_style(def_msg)}]{def_msg}[/] '{item_path[:90]}' ({source_config_name}): Ungültiger Inhalt oder kein Titel.")
                            console.print(Text.from_markup(log_line_str), overflow="ellipsis")
                            live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                            live_status["session_rules_processed"] += 1
                    except yaml.YAMLError as e_yaml:
                        error_message = str(e_yaml).replace('\n', ' ').replace('\r', '')
                        def_msg = "[Defekte Regel]"
                        log_line_str = (f"[{get_elapsed_time_str(overall_start_time)}]   "
                                        f"[{get_status_style(def_msg)}]{def_msg}[/] '{item_path[:90]}' ({source_config_name}): Ungültiges YAML. ")
                        console.print(Text.from_markup(log_line_str), overflow="ellipsis")
                        live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                        live_status["session_rules_processed"] += 1
                else:
                    live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                    live_status["session_rules_processed"] += 1
            elif item.get('type') == 'dir':
                dir_api_url = item.get('url')
                if dir_api_url:
                    fetch_and_process_github_directory(dir_api_url, source_config_name, base_request_headers, live_status, overall_start_time)
            time.sleep(0.005)
    except json.JSONDecodeError as e_json:
        console.print(f"[{get_elapsed_time_str(overall_start_time)}]   [red]JSON Fehler[/red] Verzeichnis {source_config_name} (...{api_dir_url[-75:]}): {str(e_json)[:150]}")
    except Exception as e_outer:
        console.print(f"[{get_elapsed_time_str(overall_start_time)}]   [red]Allg. Fehler[/red] Verzeichnis {source_config_name} (...{api_dir_url[-75:]}): {str(e_outer)[:150]}")


def process_source(source_config, live_status: dict, overall_start_time: float):
    source_name = source_config['name']
    source_url = source_config['url']
    console.print(f"[{get_elapsed_time_str(overall_start_time)}] Processing Source: [bold magenta]{source_name}[/bold magenta] (URL: {source_url[:105]}...)")
    request_headers = {'User-Agent': USER_AGENT}

    if source_config['type'] == 'github_repo_folder':
        github_headers = {'User-Agent': USER_AGENT, 'Accept': 'application/vnd.github.v3+json'}
        if source_config.get('github_token'): github_headers['Authorization'] = f"token {source_config['github_token']}"
        fetch_and_process_github_directory(source_url, source_name, github_headers, live_status, overall_start_time)
    elif source_config['type'] == 'single_file_yaml':
        content = fetch_url_content(source_url, request_headers, source_name, overall_start_time)
        if content:
            try:
                cleaned_content = content.replace('\xa0', ' ').replace('\ufeff', '')
                rule_data = yaml.safe_load(cleaned_content)
                if isinstance(rule_data, dict) and rule_data.get('title'):
                    store_rule(rule_data, cleaned_content, source_name, source_url, live_status, overall_start_time)
                else:
                    def_msg = "[Defekte Regel]"
                    log_line_str = (f"[{get_elapsed_time_str(overall_start_time)}]   "
                                    f"[{get_status_style(def_msg)}]{def_msg}[/] (Einzeldatei) '{source_name[:75]}': Ungültiger Inhalt/Titel.")
                    console.print(Text.from_markup(log_line_str), overflow="ellipsis")
                    live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                    live_status["session_rules_processed"] += 1
            except yaml.YAMLError as e_yaml:
                error_message = str(e_yaml).replace('\n', ' ').replace('\r', '')
                def_msg = "[Defekte Regel]"
                log_line_str = (f"[{get_elapsed_time_str(overall_start_time)}]   "
                                f"[{get_status_style(def_msg)}]{def_msg}[/] (Einzeldatei) '{source_name[:75]}': Ungültiges YAML.")
                console.print(Text.from_markup(log_line_str), overflow="ellipsis")
                live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                live_status["session_rules_processed"] += 1
            except Exception as e_single:
                 console.print(f"[{get_elapsed_time_str(overall_start_time)}]   [red]Fehler[/red] Verarbeitung Einzeldatei '{source_name[:75]}': {str(e_single)[:150]}")
                 live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                 live_status["session_rules_processed"] += 1
        else:
            live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
            live_status["session_rules_processed"] += 1
    elif source_config['type'] == 'raw_text_regex':
        content = fetch_url_content(source_url, request_headers, source_name, overall_start_time)
        if content:
            rule_pattern = re.compile(source_config.get('rule_regex', r"(?sm)(^title:.*?)(?=^title:|\Z)"))
            matches = list(rule_pattern.finditer(content))
            console.print(f"[{get_elapsed_time_str(overall_start_time)}]   {len(matches)} Regex-Matches gefunden in '{source_name}'.")
            for i, match in enumerate(matches):
                raw_rule_segment = match.group(1).strip()
                try:
                    cleaned_segment = raw_rule_segment.replace('\xa0', ' ').replace('\ufeff', '')
                    rule_data = yaml.safe_load(cleaned_segment)
                    if isinstance(rule_data, dict) and rule_data.get('title'):
                        store_rule(rule_data, cleaned_segment, source_name, f"{source_url} (Match {i+1})", live_status, overall_start_time)
                    else:
                        def_msg = "[Defekte Regel]"
                        log_line_str = (f"[{get_elapsed_time_str(overall_start_time)}]   "
                                        f"[{get_status_style(def_msg)}]{def_msg}[/] (Regex Match {i+1}, {source_name[:60]}): Ungültiger Inhalt oder kein Titel.")
                        console.print(Text.from_markup(log_line_str), overflow="ellipsis")
                        live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                        live_status["session_rules_processed"] += 1
                except yaml.YAMLError as e_yaml:
                    error_message = str(e_yaml).replace('\n', ' ').replace('\r', '')
                    def_msg = "[Defekte Regel]"
                    log_line_str = (f"[{get_elapsed_time_str(overall_start_time)}]   "
                                    f"[{get_status_style(def_msg)}]{def_msg}[/] (Regex Match {i+1}, {source_name[:60]}): Ungültiges YAML. "
                                    f"Fehler: {error_message[:150]}")
                    console.print(Text.from_markup(log_line_str), overflow="ellipsis")
                    live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                    live_status["session_rules_processed"] += 1
                except Exception as e_regex:
                    console.print(f"[{get_elapsed_time_str(overall_start_time)}]   [red]Fehler[/red] Verarbeitung Regex Match {i+1} ({source_name[:60]}): {str(e_regex)[:150]}")
                    live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                    live_status["session_rules_processed"] += 1
        else:
            live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
            live_status["session_rules_processed"] += 1
    else:
        console.print(f"[{get_elapsed_time_str(overall_start_time)}]   [yellow]Unbekannter Quelltyp[/yellow]: {source_config['type']} für Quelle '{source_name}'.")

    console.print(f"[{get_elapsed_time_str(overall_start_time)}] Source '{source_name}' [bold green]completed[/bold green].")


def main():
    console.rule("[bold]Sigma Rule Collector[/bold]")
    console.print("Starting...\nPress Enter to continue (or Ctrl+C to cancel).")
    try:
        input()
    except KeyboardInterrupt:
        console.print("\nStart cancelled by user.")
        return

    overall_start_time = time.time()
    live_status = {
        "session_rules_processed": 0, "session_rules_added_new": 0,
        "session_rules_updated_content": 0, "session_rules_updated_ts": 0,
        "session_rules_added_version": 0, "session_rules_skipped_no_title": 0,
        "session_rules_skipped_other": 0, "session_rules_skipped_defective": 0
    }

    try:
        init_db(overall_start_time)

        if not os.path.exists(CONFIG_FILE):
            console.print(f"[{get_elapsed_time_str(overall_start_time)}] [red]❌ Config file '{CONFIG_FILE}' not found.[/red]")
            example_config = [{"name": "SigmaHQ Windows (Example)", "url": "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows", "type": "github_repo_folder", "github_token": "", "enabled": True}, {"name": "Single Rule (Example)", "url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_lolbas_forfiles.yml", "type": "single_file_yaml", "enabled": True}]
            try:
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f_cfg: json.dump(example_config, f_cfg, indent=4)
                console.print(f"[{get_elapsed_time_str(overall_start_time)}] ℹ️ Example config '{CONFIG_FILE}' created. Please adapt and restart.")
            except IOError as e_io:
                console.print(f"[{get_elapsed_time_str(overall_start_time)}] [red]❌ Error creating example config: {e_io}[/red]")
            return

        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f: config_data = json.load(f)
        except json.JSONDecodeError as e_json_cfg:
            console.print(f"[{get_elapsed_time_str(overall_start_time)}] [red]❌ Error parsing config file '{CONFIG_FILE}': {e_json_cfg}. Please check syntax.[/red]")
            return

        enabled_sources = [s for s in config_data if s.get("enabled", False)]
        disabled_source_names = [s.get('name', 'Unnamed') for s in config_data if not s.get("enabled", False)]

        if not enabled_sources:
            console.print(f"[{get_elapsed_time_str(overall_start_time)}] [yellow]No active sources configured. Exiting.[/yellow]")
        else:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=None),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=console,
                transient=False
            ) as source_progress_bar:
                overall_task_id = source_progress_bar.add_task("Overall Source Progress", total=len(enabled_sources))
                for source_cfg in enabled_sources:
                    process_source(source_cfg, live_status, overall_start_time)
                    source_progress_bar.advance(overall_task_id)

        if disabled_source_names:
            console.print(f"\n[{get_elapsed_time_str(overall_start_time)}] [dim]The following sources were skipped (disabled):[/dim]")
            for name in disabled_source_names:
                console.print(f"[dim]  - {name}[/dim]")

    except Exception as e_critical_outer:
        console.print(f"\n[{get_elapsed_time_str(overall_start_time)}] [bold red]A critical error occurred: {e_critical_outer}[/bold red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
    finally:
        final_elapsed_time = get_elapsed_time_str(overall_start_time)
        console.rule(f"[{final_elapsed_time}] [bold green]Processing Completed[/bold green]")

        stats_table = Table(title=f"Overall Statistics (Total Run Time: {final_elapsed_time})", show_lines=True, width=100)
        stats_table.add_column("Statistic", style="dim", no_wrap=True, min_width=35)
        stats_table.add_column("Value", justify="right", min_width=10)

        stats_table.add_row("Attempted Rules (processed or skipped)", f"[bold default]{live_status.get('session_rules_processed', 0)}[/bold default]")
        stats_table.add_row("New Rules Added", f"[bold green]{live_status.get('session_rules_added_new', 0)}[/bold green]")
        stats_table.add_row("Rules Updated (Content)", f"[bold cyan]{live_status.get('session_rules_updated_content', 0)}[/bold cyan]")
        stats_table.add_row("Rules Updated (Timestamp/✅)", f"[bold cyan]{live_status.get('session_rules_updated_ts', 0)}[/bold cyan]") # TS ist auch cyan
        stats_table.add_row("New Versions Created", f"[bold magenta]{live_status.get('session_rules_added_version', 0)}[/bold magenta]")
        stats_table.add_row("Skipped (No Title)", f"[bold yellow]{live_status.get('session_rules_skipped_no_title', 0)}[/bold yellow]")
        stats_table.add_row("Skipped (Defective/YAML Error)", f"[bold orange_red1]{live_status.get('session_rules_skipped_defective', 0)}[/bold orange_red1]")
        stats_table.add_row("Skipped (Other reasons/Unchanged)", f"[yellow]{live_status.get('session_rules_skipped_other', 0)}[/yellow]")
        console.print(stats_table)

        console.print(f"\nSee '{DB_FILE}' for the database and '{RULES_DIR}/' for the rule files.")

if __name__ == '__main__':
    main()