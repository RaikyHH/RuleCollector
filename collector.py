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
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Global Config ---
CONFIG_FILE = 'config.json'
DB_FILE = 'sigma_rules.db'
RULES_DIR = 'sigma_rules_files'
STATE_DIR = 'sync_state'
REQUEST_TIMEOUT = 30
USER_AGENT = "SigmaRuleCollector/1.0"
MAX_WORKERS = 20

# Per-thread requests session so we get connection pooling for free
_thread_local = threading.local()

# Serialize SQLite writes — sqlite3 connections aren't safe to share across threads
_db_lock = threading.Lock()


def _get_session() -> requests.Session:
    sess = getattr(_thread_local, "session", None)
    if sess is None:
        sess = requests.Session()
        _thread_local.session = sess
    return sess


def get_elapsed_time_str(start_time_seconds: float) -> str:
    """Konvertiert verstrichene Sekunden seit start_time_seconds in HH:MM:SS."""
    elapsed_total_seconds = int(time.time() - start_time_seconds)
    hours, remainder = divmod(elapsed_total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def normalize_title(title):
    if not title: return ""
    return title.strip().lower()


def _parse_sigma_date(value) -> str | None:
    """Parse a Sigma date field (YYYY/MM/DD or YYYY-MM-DD) and return ISO date string, or None."""
    if not value:
        return None
    s = str(value).strip().replace('/', '-')
    m = re.match(r'^(\d{4}-\d{2}-\d{2})$', s)
    if m:
        return m.group(1)
    m2 = re.match(r'^(\d{4}-\d{2}-\d{2})[ T]', s)
    if m2:
        return m2.group(1)
    return None


def _extract_authored_at(parsed_rule_data: dict) -> str | None:
    """Return the author-facing last-change date: 'modified' first, then 'date'."""
    return _parse_sigma_date(parsed_rule_data.get('modified')) or \
           _parse_sigma_date(parsed_rule_data.get('date'))


def _extract_sigmahq_path(source_url: str) -> list:
    """
    Extract all folder segments (excluding filename) from a SigmaHQ URL, title-cased.
    E.g. .../rules/windows/file/file_access/rule.yml → ['Windows', 'File', 'File Access']
    Returns [] if URL does not match or has no folder segments.
    """
    if not source_url:
        return []
    m = re.search(r'/rules/(.+)', source_url)
    if not m:
        return []
    parts = m.group(1).split('/')
    if len(parts) < 2:
        return []
    folder_parts = parts[:-1]
    return [p.replace('_', ' ').title() for p in folder_parts]


def _extract_sigmahq_categories(source_url: str):
    """Extract (cat1, cat2) for the legacy DB columns."""
    path = _extract_sigmahq_path(source_url)
    cat1 = path[0] if len(path) >= 1 else None
    cat2 = path[1] if len(path) >= 2 else None
    return cat1, cat2


def _parse_github_url(url: str) -> dict | None:
    """
    Parse a GitHub Contents API URL into owner/repo/path_prefix.
    Returns None if the URL doesn't match.
    """
    if not url:
        return None
    m = re.match(
        r'^https?://api\.github\.com/repos/([^/]+)/([^/]+)/contents/?(.*?)/?(?:\?.*)?$',
        url.strip()
    )
    if not m:
        return None
    return {
        'owner': m.group(1),
        'repo': m.group(2),
        'path_prefix': m.group(3) or '',
    }


def _sanitize_state_filename(name: str) -> str:
    return re.sub(r'\W', '_', name) + '.json'


def _load_state(source_name: str) -> dict:
    path = os.path.join(STATE_DIR, _sanitize_state_filename(source_name))
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save_state(source_name: str, state: dict) -> None:
    if not os.path.exists(STATE_DIR):
        try:
            os.makedirs(STATE_DIR)
        except OSError:
            pass
    path = os.path.join(STATE_DIR, _sanitize_state_filename(source_name))
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)
    except IOError as e:
        print(f"  Warnung: State-Datei konnte nicht geschrieben werden: {e}")


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
            source_url TEXT, first_seen_at TIMESTAMP, last_updated_at TIMESTAMP, rule_hash TEXT,
            rule_authored_at TEXT, sigmahq_category_1 TEXT, sigmahq_category_2 TEXT, sigmahq_path TEXT
        )''')
        existing_cols = [row[1] for row in cursor.execute('PRAGMA table_info(sigma_rules)').fetchall()]
        if 'rule_authored_at' not in existing_cols:
            cursor.execute('ALTER TABLE sigma_rules ADD COLUMN rule_authored_at TEXT')
            print(f"[{get_elapsed_time_str(overall_start_time)}] Spalte 'rule_authored_at' zur DB hinzugefügt.")
        if 'sigmahq_category_1' not in existing_cols:
            cursor.execute('ALTER TABLE sigma_rules ADD COLUMN sigmahq_category_1 TEXT')
            print(f"[{get_elapsed_time_str(overall_start_time)}] Spalte 'sigmahq_category_1' zur DB hinzugefügt.")
        if 'sigmahq_category_2' not in existing_cols:
            cursor.execute('ALTER TABLE sigma_rules ADD COLUMN sigmahq_category_2 TEXT')
            print(f"[{get_elapsed_time_str(overall_start_time)}] Spalte 'sigmahq_category_2' zur DB hinzugefügt.")
        if 'sigmahq_path' not in existing_cols:
            cursor.execute('ALTER TABLE sigma_rules ADD COLUMN sigmahq_path TEXT')
            print(f"[{get_elapsed_time_str(overall_start_time)}] Spalte 'sigmahq_path' zur DB hinzugefügt.")
        conn.commit()
        print(f"[{get_elapsed_time_str(overall_start_time)}] Datenbank initialisiert.")
    except Exception as e:
        print(f"[{get_elapsed_time_str(overall_start_time)}] Kritischer Fehler bei DB-Initialisierung: {e}. Skript wird beendet.")
        raise
    finally:
        if conn:
            conn.close()


def store_rule(conn, parsed_rule_data, raw_rule_content, source_name, source_url, live_status: dict, overall_start_time: float):
    """
    Insert/update a rule using a caller-provided sqlite connection.
    Caller is responsible for opening, locking, committing and closing the connection.
    """
    rule_processed_for_stats = True
    new_rule_title_from_file = parsed_rule_data.get('title', 'Unbenannte Regel').strip()

    db_status_text = "DB Unverändert"
    file_status_text = "Datei N/A"
    filename_for_saving = "ErrorInFilenameGeneration.yml"

    LOG_RULE_TITLE_LEN = 65
    LOG_SOURCE_NAME_LEN = 22
    LOG_FILENAME_DISPLAY_LEN = 35

    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        current_time = datetime.now()
        authored_at = _extract_authored_at(parsed_rule_data)
        sigmahq_path_list = _extract_sigmahq_path(source_url)
        sigmahq_cat1 = sigmahq_path_list[0] if len(sigmahq_path_list) >= 1 else None
        sigmahq_cat2 = sigmahq_path_list[1] if len(sigmahq_path_list) >= 2 else None
        sigmahq_path_json = json.dumps(sigmahq_path_list) if sigmahq_path_list else None

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
            db_status_text = "Übersprungen (kein Titel)"
            file_status_text = "Datei Übersprungen"
            log_line_str = (
                f"[{get_elapsed_time_str(overall_start_time)}] "
                f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' "
                f"({source_name[:LOG_SOURCE_NAME_LEN]}): "
                f"{db_status_text}"
            )
            print(log_line_str)
            live_status["session_rules_skipped_no_title"] = live_status.get("session_rules_skipped_no_title", 0) + 1
            rule_processed_for_stats = False
            return

        cleaned_title_for_filename = re.sub(r'[^\w\._-]+', '_', new_rule_title_from_file)
        filename_for_saving = f"{cleaned_title_for_filename[:100]}_{new_rule_hash[:8]}.yml"

        try:
            if not os.path.exists(RULES_DIR): file_status_text = "Datei Fehler (Ordner fehlt)"
            else:
                filepath = os.path.join(RULES_DIR, filename_for_saving)
                with open(filepath, 'w', encoding='utf-8') as f_rule: f_rule.write(raw_rule_content)
                file_status_text = f"Datei OK: '{filename_for_saving}'"
        except Exception as e_file: file_status_text = f"Datei Fehler: {str(e_file)[:75]}"

        cursor.execute("SELECT * FROM sigma_rules WHERE id = ?", (new_rule_id_from_file,))
        db_rule_by_id = cursor.fetchone()

        if db_rule_by_id:
            if db_rule_by_id['rule_hash'] == new_rule_hash:
                if authored_at:
                    cursor.execute("UPDATE sigma_rules SET last_updated_at=?, source_name=?, source_url=?, rule_authored_at=? WHERE id=?", (current_time, source_name, source_url, authored_at, new_rule_id_from_file))
                else:
                    cursor.execute("UPDATE sigma_rules SET last_updated_at=?, source_name=?, source_url=? WHERE id=?", (current_time, source_name, source_url, new_rule_id_from_file))
                db_status_text = "DB TS \u2705"
                live_status["session_rules_updated_ts"] = live_status.get("session_rules_updated_ts", 0) + 1
            else:
                logsource = parsed_rule_data.get('logsource', {}); detection = parsed_rule_data.get('detection', {})
                cursor.execute("UPDATE sigma_rules SET title=?, status=?, description=?, author=?, \"references\"=?, logsource_category=?, logsource_product=?, detection=?, falsepositives=?, level=?, tags=?, raw_rule=?, source_name=?, source_url=?, last_updated_at=?, rule_hash=?, rule_authored_at=?, sigmahq_category_1=?, sigmahq_category_2=?, sigmahq_path=? WHERE id=?",
                               (new_rule_title_from_file, parsed_rule_data.get('status'), parsed_rule_data.get('description'), parsed_rule_data.get('author'), json.dumps(parsed_rule_data.get('references', [])), logsource.get('category'), logsource.get('product'), json.dumps(detection), json.dumps(parsed_rule_data.get('falsepositives', [])), parsed_rule_data.get('level'), json.dumps(parsed_rule_data.get('tags', [])), raw_rule_content, source_name, source_url, current_time, new_rule_hash, authored_at, sigmahq_cat1, sigmahq_cat2, sigmahq_path_json, new_rule_id_from_file))
                db_status_text = "DB Inhalt Aktualisiert"
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
                cursor.execute("INSERT INTO sigma_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (new_rule_id_from_file, new_rule_title_from_file, parsed_rule_data.get('status'), parsed_rule_data.get('description'), parsed_rule_data.get('author'), json.dumps(parsed_rule_data.get('references', [])), logsource.get('category'), logsource.get('product'), json.dumps(detection), json.dumps(parsed_rule_data.get('falsepositives', [])), parsed_rule_data.get('level'), json.dumps(parsed_rule_data.get('tags', [])), raw_rule_content, source_name, source_url, current_time, current_time, new_rule_hash, authored_at, sigmahq_cat1, sigmahq_cat2, sigmahq_path_json))
                db_status_text = "DB Neu Hinzugefügt"
                live_status["session_rules_added_new"] = live_status.get("session_rules_added_new", 0) + 1
            else:
                title_family_rules_db.sort(key=lambda r: r['first_seen_at_dt'])
                primary_rule = title_family_rules_db[0]
                hash_match_in_family = any(r['rule_hash'] == new_rule_hash for r in title_family_rules_db)
                if hash_match_in_family:
                    matched_rule_id_obj = next(r['id'] for r in title_family_rules_db if r['rule_hash'] == new_rule_hash)
                    if authored_at:
                        cursor.execute("UPDATE sigma_rules SET last_updated_at=?, source_name=?, source_url=?, rule_authored_at=? WHERE id=?", (current_time, source_name, source_url, authored_at, str(matched_rule_id_obj)))
                    else:
                        cursor.execute("UPDATE sigma_rules SET last_updated_at=?, source_name=?, source_url=? WHERE id=?", (current_time, source_name, source_url, str(matched_rule_id_obj)))
                    db_status_text = "DB TS \u2705 (Fam)"
                    live_status["session_rules_updated_ts"] = live_status.get("session_rules_updated_ts", 0) + 1
                else:
                    try: primary_detection_dict = json.loads(primary_rule['detection'])
                    except (json.JSONDecodeError, TypeError): primary_detection_dict = {}
                    if new_rule_detection_dict == primary_detection_dict:
                        if authored_at:
                            cursor.execute("UPDATE sigma_rules SET last_updated_at=?, source_name=?, source_url=?, rule_authored_at=? WHERE id=?", (current_time, source_name, source_url, authored_at, str(primary_rule['id'])))
                        else:
                            cursor.execute("UPDATE sigma_rules SET last_updated_at=?, source_name=?, source_url=? WHERE id=?", (current_time, source_name, source_url, str(primary_rule['id'])))
                        db_status_text = "DB TS \u2705 (Det)"
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
                        cursor.execute("INSERT INTO sigma_rules VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (new_rule_id_from_file, versioned_title, parsed_rule_data.get('status'), parsed_rule_data.get('description'), parsed_rule_data.get('author'), json.dumps(parsed_rule_data.get('references', [])), logsource.get('category'), logsource.get('product'), json.dumps(detection), json.dumps(parsed_rule_data.get('falsepositives', [])), parsed_rule_data.get('level'), json.dumps(parsed_rule_data.get('tags', [])), raw_rule_content, source_name, source_url, current_time, current_time, new_rule_hash, authored_at, sigmahq_cat1, sigmahq_cat2, sigmahq_path_json))
                        db_status_text = f"DB Als Version '{versioned_title}' Hinzugefügt"
                        live_status["session_rules_added_version"] = live_status.get("session_rules_added_version", 0) + 1

        log_display_filename = filename_for_saving
        if len(filename_for_saving) > LOG_FILENAME_DISPLAY_LEN:
            log_display_filename = filename_for_saving[:LOG_FILENAME_DISPLAY_LEN-3] + "..."

        current_file_status_for_log = file_status_text
        if file_status_text.startswith("Datei OK:"):
             current_file_status_for_log = f"Datei OK: '{log_display_filename}'"

        log_line_str = (
            f"[{get_elapsed_time_str(overall_start_time)}] "
            f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' "
            f"({source_name[:LOG_SOURCE_NAME_LEN]}): "
            f"{db_status_text} - "
            f"{current_file_status_for_log}"
        )
        print(log_line_str)

    except sqlite3.Error as e_sql:
        db_status_text = f"DB-Fehler: {str(e_sql)[:100]}"
        log_line_str = (
            f"[{get_elapsed_time_str(overall_start_time)}] "
            f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' "
            f"({source_name[:LOG_SOURCE_NAME_LEN]}): "
            f"{db_status_text} - "
            f"{file_status_text}"
        )
        print(log_line_str)
        rule_processed_for_stats = False
    except Exception as e_gen:
        db_status_text = f"Allg. Fehler: {str(e_gen)[:100]}"
        log_line_str = (
            f"[{get_elapsed_time_str(overall_start_time)}] "
            f"'{new_rule_title_from_file[:LOG_RULE_TITLE_LEN]}' "
            f"({source_name[:LOG_SOURCE_NAME_LEN]}): "
            f"{db_status_text} - "
            f"{file_status_text}"
        )
        print(log_line_str)
        rule_processed_for_stats = False
    finally:
        if rule_processed_for_stats:
            live_status["session_rules_processed"] = live_status.get("session_rules_processed", 0) + 1
        elif not (db_status_text == "Übersprungen (kein Titel)"):
            live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1


def fetch_url_content(url, headers, source_name: str, overall_start_time: float):
    try:
        sess = _get_session()
        response = sess.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        if response.status_code in (401, 403) and 'Authorization' in headers:
            print(f"[{get_elapsed_time_str(overall_start_time)}]   Token abgelehnt für {source_name}, versuche ohne Auth...")
            fallback_headers = {k: v for k, v in headers.items() if k != 'Authorization'}
            response = sess.get(url, timeout=REQUEST_TIMEOUT, headers=fallback_headers)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   Netzwerkfehler für {source_name} (URL: ...{url[-90:]}): {str(e)[:150]}")
        return None
    except Exception as e_gen:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   Unerwarteter Fehler beim Download für {source_name} (URL: ...{url[-90:]}): {str(e_gen)[:150]}")
        return None


def _fetch_head_tree_sha(owner: str, repo: str, headers: dict, source_name: str, overall_start_time: float) -> str | None:
    """Fetch the tree SHA of HEAD for the given repo. Returns None on failure."""
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/HEAD"
    body = fetch_url_content(url, headers, source_name, overall_start_time)
    if not body:
        return None
    try:
        data = json.loads(body)
        if isinstance(data, dict) and 'commit' in data:
            return data['commit'].get('tree', {}).get('sha')
        if isinstance(data, dict) and 'message' in data:
            print(f"[{get_elapsed_time_str(overall_start_time)}]   GitHub API Fehler ({source_name}): {data.get('message')[:150]}")
        return None
    except json.JSONDecodeError as e:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   JSON-Fehler beim Lesen des HEAD-Commits ({source_name}): {e}")
        return None


def _fetch_full_tree(owner: str, repo: str, tree_sha: str, headers: dict, source_name: str, overall_start_time: float) -> list | None:
    """Recursively fetch the full tree at tree_sha. Returns the tree list or None."""
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}?recursive=1"
    body = fetch_url_content(url, headers, source_name, overall_start_time)
    if not body:
        return None
    try:
        data = json.loads(body)
        if not isinstance(data, dict) or 'tree' not in data:
            print(f"[{get_elapsed_time_str(overall_start_time)}]   Unerwartete Tree-Antwort für {source_name}.")
            return None
        if data.get('truncated'):
            print(f"[{get_elapsed_time_str(overall_start_time)}]   Warnung: Tree-Antwort für {source_name} ist truncated — einige Dateien fehlen evtl.")
        return data['tree']
    except json.JSONDecodeError as e:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   JSON-Fehler beim Lesen des Trees ({source_name}): {e}")
        return None


def _filter_yaml_blobs(tree: list, path_prefix: str) -> list:
    """Pick only YAML blob entries under path_prefix."""
    prefix = path_prefix.strip('/')
    out = []
    for entry in tree:
        if entry.get('type') != 'blob':
            continue
        path = entry.get('path', '')
        if not path.endswith(('.yml', '.yaml')):
            continue
        if prefix and not (path == prefix or path.startswith(prefix + '/')):
            continue
        out.append({'path': path, 'sha': entry.get('sha')})
    return out


def _download_blob(owner: str, repo: str, file_path: str, headers: dict, source_name: str, overall_start_time: float) -> tuple[str, str | None]:
    """Download a single blob via raw.githubusercontent.com. Returns (download_url, content)."""
    download_url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{file_path}"
    # raw.githubusercontent.com doesn't need the API token; pass plain UA
    raw_headers = {'User-Agent': USER_AGENT}
    content = fetch_url_content(download_url, raw_headers, source_name, overall_start_time)
    return download_url, content


def _process_yaml_payload(conn, file_path: str, download_url: str, file_content: str,
                          source_name: str, live_status: dict, overall_start_time: float) -> None:
    """Parse one YAML blob and route to store_rule. Holds the DB lock during the write."""
    try:
        cleaned_content = file_content.replace('\xa0', ' ').replace('\ufeff', '')
        rule_data = yaml.safe_load(cleaned_content)
        if isinstance(rule_data, dict) and rule_data.get('title'):
            with _db_lock:
                store_rule(conn, rule_data, cleaned_content, source_name, download_url, live_status, overall_start_time)
                conn.commit()
        else:
            print(f"[{get_elapsed_time_str(overall_start_time)}]   "
                  f"Defekte Regel '{file_path[:90]}' ({source_name}): Ungültiger Inhalt oder kein Titel.")
            live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
            live_status["session_rules_processed"] += 1
    except yaml.YAMLError as e_yaml:
        error_message = str(e_yaml).replace('\n', ' ').replace('\r', '')
        print(f"[{get_elapsed_time_str(overall_start_time)}]   "
              f"Defekte Regel '{file_path[:90]}' ({source_name}): Ungültiges YAML. "
              f"Fehler: {error_message[:150]}")
        live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
        live_status["session_rules_processed"] += 1


def _touch_unchanged_rules(conn, download_urls: list, overall_start_time: float) -> int:
    """Bulk-update last_updated_at for rules whose source_url is in the unchanged blob list."""
    if not download_urls:
        return 0
    now = datetime.now()
    # Use chunks to stay within SQLite's variable limit (999 per statement)
    CHUNK = 900
    touched = 0
    with _db_lock:
        cur = conn.cursor()
        for i in range(0, len(download_urls), CHUNK):
            chunk = download_urls[i:i + CHUNK]
            placeholders = ','.join('?' * len(chunk))
            cur.execute(
                f"UPDATE sigma_rules SET last_updated_at=? WHERE source_url IN ({placeholders})",
                [now] + chunk
            )
            touched += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        conn.commit()
    return touched


def fetch_and_process_github_repo(source_config, base_request_headers, live_status, overall_start_time):
    """Tree-API based incremental sync for a github_repo_folder source."""
    source_name = source_config['name']
    source_url = source_config['url']

    parsed = _parse_github_url(source_url)
    if not parsed:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   Konnte GitHub-URL nicht parsen: {source_url}")
        return

    owner, repo, path_prefix = parsed['owner'], parsed['repo'], parsed['path_prefix']

    # 1. Get HEAD tree SHA
    head_tree_sha = _fetch_head_tree_sha(owner, repo, base_request_headers, source_name, overall_start_time)
    if not head_tree_sha:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   Konnte HEAD-Tree-SHA nicht abrufen für {source_name}, überspringe.")
        return

    # 2. Compare with state
    state = _load_state(source_name)
    prev_tree_sha = state.get('tree_sha')
    prev_files = state.get('files', {}) or {}

    if prev_tree_sha == head_tree_sha and prev_files:
        print(f"[{get_elapsed_time_str(overall_start_time)}] Source '{source_name}': No changes since last sync (tree {head_tree_sha[:10]}).")
        state['last_sync'] = datetime.now().isoformat()
        _save_state(source_name, state)
        return

    # 3. Fetch the full tree, filter to relevant YAML blobs
    tree = _fetch_full_tree(owner, repo, head_tree_sha, base_request_headers, source_name, overall_start_time)
    if tree is None:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   Tree-Abruf fehlgeschlagen für {source_name}.")
        return

    yaml_blobs = _filter_yaml_blobs(tree, path_prefix)
    total = len(yaml_blobs)

    # 4. Diff against previous state
    new_files = []
    changed_files = []
    unchanged_files = []
    for blob in yaml_blobs:
        prev_sha = prev_files.get(blob['path'])
        if prev_sha is None:
            new_files.append(blob)
        elif prev_sha != blob['sha']:
            changed_files.append(blob)
        else:
            unchanged_files.append(blob)

    print(f"[{get_elapsed_time_str(overall_start_time)}] Source '{source_name}': "
          f"{total} files total, {len(changed_files)} changed, {len(new_files)} new, "
          f"{len(unchanged_files)} unchanged (skipped download)")

    # 5. Touch unchanged rules in one bulk UPDATE
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    try:
        if unchanged_files:
            unchanged_urls = [
                f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{b['path']}"
                for b in unchanged_files
            ]
            touched = _touch_unchanged_rules(conn, unchanged_urls, overall_start_time)
            print(f"[{get_elapsed_time_str(overall_start_time)}]   {touched} unveränderte Regeln in DB getoucht.")

        # 6. Download new + changed blobs in parallel
        to_download = new_files + changed_files
        if to_download:
            print(f"[{get_elapsed_time_str(overall_start_time)}]   Lade {len(to_download)} Dateien parallel ({MAX_WORKERS} Worker)...")

            def _worker(blob):
                file_path = blob['path']
                download_url, content = _download_blob(owner, repo, file_path,
                                                       base_request_headers, source_name, overall_start_time)
                if content is None:
                    return file_path, download_url, None
                return file_path, download_url, content

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futures = [pool.submit(_worker, b) for b in to_download]
                for fut in as_completed(futures):
                    try:
                        file_path, download_url, content = fut.result()
                    except Exception as e:
                        print(f"[{get_elapsed_time_str(overall_start_time)}]   Worker-Fehler: {e}")
                        live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                        live_status["session_rules_processed"] += 1
                        continue
                    if content is None:
                        live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                        live_status["session_rules_processed"] += 1
                        continue
                    _process_yaml_payload(conn, file_path, download_url, content,
                                          source_name, live_status, overall_start_time)
    finally:
        try:
            conn.commit()
        except Exception:
            pass
        conn.close()

    # 7. Persist new state
    new_state = {
        'last_sync': datetime.now().isoformat(),
        'tree_sha': head_tree_sha,
        'files': {b['path']: b['sha'] for b in yaml_blobs},
    }
    _save_state(source_name, new_state)


def process_source(source_config, live_status: dict, overall_start_time: float):
    source_name = source_config['name']
    source_url = source_config['url']
    print(f"[{get_elapsed_time_str(overall_start_time)}] Processing Source: {source_name} (URL: {source_url[:105]}...)")
    request_headers = {'User-Agent': USER_AGENT}

    if source_config['type'] == 'github_repo_folder':
        github_headers = {'User-Agent': USER_AGENT, 'Accept': 'application/vnd.github.v3+json'}
        token = source_config.get('github_token') or os.environ.get('GITHUB_TOKEN', '')
        if token:
            github_headers['Authorization'] = f"token {token}"
        fetch_and_process_github_repo(source_config, github_headers, live_status, overall_start_time)

    elif source_config['type'] == 'single_file_yaml':
        content = fetch_url_content(source_url, request_headers, source_name, overall_start_time)
        conn = sqlite3.connect(DB_FILE)
        try:
            if content:
                try:
                    cleaned_content = content.replace('\xa0', ' ').replace('\ufeff', '')
                    rule_data = yaml.safe_load(cleaned_content)
                    if isinstance(rule_data, dict) and rule_data.get('title'):
                        with _db_lock:
                            store_rule(conn, rule_data, cleaned_content, source_name, source_url, live_status, overall_start_time)
                            conn.commit()
                    else:
                        print(f"[{get_elapsed_time_str(overall_start_time)}]   "
                              f"Defekte Regel (Einzeldatei) '{source_name[:75]}': Ungültiger Inhalt oder kein Titel.")
                        live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                        live_status["session_rules_processed"] += 1
                except yaml.YAMLError as e_yaml:
                    error_message = str(e_yaml).replace('\n', ' ').replace('\r', '')
                    print(f"[{get_elapsed_time_str(overall_start_time)}]   "
                          f"Defekte Regel (Einzeldatei) '{source_name[:75]}': Ungültiges YAML. "
                          f"Fehler: {error_message[:150]}")
                    live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                    live_status["session_rules_processed"] += 1
                except Exception as e_single:
                    print(f"[{get_elapsed_time_str(overall_start_time)}]   Fehler Verarbeitung Einzeldatei '{source_name[:75]}': {str(e_single)[:150]}")
                    live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                    live_status["session_rules_processed"] += 1
            else:
                live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                live_status["session_rules_processed"] += 1
        finally:
            conn.close()

    elif source_config['type'] == 'raw_text_regex':
        content = fetch_url_content(source_url, request_headers, source_name, overall_start_time)
        conn = sqlite3.connect(DB_FILE)
        try:
            if content:
                rule_pattern = re.compile(source_config.get('rule_regex', r"(?sm)(^title:.*?)(?=^title:|\Z)"))
                matches = list(rule_pattern.finditer(content))
                print(f"[{get_elapsed_time_str(overall_start_time)}]   {len(matches)} Regex-Matches gefunden in '{source_name}'.")
                for i, match in enumerate(matches):
                    raw_rule_segment = match.group(1).strip()
                    try:
                        cleaned_segment = raw_rule_segment.replace('\xa0', ' ').replace('\ufeff', '')
                        rule_data = yaml.safe_load(cleaned_segment)
                        if isinstance(rule_data, dict) and rule_data.get('title'):
                            with _db_lock:
                                store_rule(conn, rule_data, cleaned_segment, source_name, f"{source_url} (Match {i+1})", live_status, overall_start_time)
                                conn.commit()
                        else:
                            print(f"[{get_elapsed_time_str(overall_start_time)}]   "
                                  f"Defekte Regel (Regex Match {i+1}, {source_name[:60]}): Ungültiger Inhalt oder kein Titel.")
                            live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                            live_status["session_rules_processed"] += 1
                    except yaml.YAMLError as e_yaml:
                        error_message = str(e_yaml).replace('\n', ' ').replace('\r', '')
                        print(f"[{get_elapsed_time_str(overall_start_time)}]   "
                              f"Defekte Regel (Regex Match {i+1}, {source_name[:60]}): Ungültiges YAML. "
                              f"Fehler: {error_message[:150]}")
                        live_status["session_rules_skipped_defective"] = live_status.get("session_rules_skipped_defective", 0) + 1
                        live_status["session_rules_processed"] += 1
                    except Exception as e_regex:
                        print(f"[{get_elapsed_time_str(overall_start_time)}]   Fehler Verarbeitung Regex Match {i+1} ({source_name[:60]}): {str(e_regex)[:150]}")
                        live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                        live_status["session_rules_processed"] += 1
            else:
                live_status["session_rules_skipped_other"] = live_status.get("session_rules_skipped_other", 0) + 1
                live_status["session_rules_processed"] += 1
        finally:
            conn.close()

    else:
        print(f"[{get_elapsed_time_str(overall_start_time)}]   Unbekannter Quelltyp: {source_config['type']} für Quelle '{source_name}'.")

    print(f"[{get_elapsed_time_str(overall_start_time)}] Source '{source_name}' completed.")


def main():
    print("--- Sigma Rule Collector ---")
    print("Starting...\nPress Enter to continue (or Ctrl+C to cancel).")
    try:
        input()
    except KeyboardInterrupt:
        print("\nStart cancelled by user.")
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

        if not os.path.exists(STATE_DIR):
            try: os.makedirs(STATE_DIR)
            except OSError: pass

        if not os.path.exists(CONFIG_FILE):
            print(f"[{get_elapsed_time_str(overall_start_time)}] Config file '{CONFIG_FILE}' not found.")
            example_config = [{"name": "SigmaHQ Windows (Example)", "url": "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows", "type": "github_repo_folder", "github_token": "", "enabled": True}, {"name": "Single Rule (Example)", "url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_lolbas_forfiles.yml", "type": "single_file_yaml", "enabled": True}]
            try:
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f_cfg: json.dump(example_config, f_cfg, indent=4)
                print(f"[{get_elapsed_time_str(overall_start_time)}] Example config '{CONFIG_FILE}' created. Please adapt and restart.")
            except IOError as e_io:
                print(f"[{get_elapsed_time_str(overall_start_time)}] Error creating example config: {e_io}")
            return

        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f: config_data = json.load(f)
        except json.JSONDecodeError as e_json_cfg:
            print(f"[{get_elapsed_time_str(overall_start_time)}] Error parsing config file '{CONFIG_FILE}': {e_json_cfg}. Please check syntax.")
            return

        enabled_sources = [s for s in config_data if s.get("enabled", False)]
        disabled_source_names = [s.get('name', 'Unnamed') for s in config_data if not s.get("enabled", False)]

        if not enabled_sources:
            print(f"[{get_elapsed_time_str(overall_start_time)}] No active sources configured. Exiting.")
        else:
            print(f"[{get_elapsed_time_str(overall_start_time)}] Found {len(enabled_sources)} active sources.")
            for i, source_cfg in enumerate(enabled_sources):
                print(f"\n[{get_elapsed_time_str(overall_start_time)}] --- Starting Source {i+1}/{len(enabled_sources)} ---")
                process_source(source_cfg, live_status, overall_start_time)
                print(f"[{get_elapsed_time_str(overall_start_time)}] --- Finished Source {i+1}/{len(enabled_sources)} ---")

        if disabled_source_names:
            print(f"\n[{get_elapsed_time_str(overall_start_time)}] The following sources were skipped (disabled):")
            for name in disabled_source_names:
                print(f"  - {name}")

    except Exception as e_critical_outer:
        print(f"\n[{get_elapsed_time_str(overall_start_time)}] A critical error occurred: {e_critical_outer}")
        print(traceback.format_exc())
    finally:
        final_elapsed_time = get_elapsed_time_str(overall_start_time)
        print(f"\n--- [{final_elapsed_time}] Processing Completed ---")

        print("\nOverall Statistics:")
        print(f"  Total Run Time: {final_elapsed_time}")
        print(f"  Attempted Rules (processed or skipped): {live_status.get('session_rules_processed', 0)}")
        print(f"  New Rules Added: {live_status.get('session_rules_added_new', 0)}")
        print(f"  Rules Updated (Content): {live_status.get('session_rules_updated_content', 0)}")
        print(f"  Rules Updated (Timestamp/\u2705): {live_status.get('session_rules_updated_ts', 0)}")
        print(f"  New Versions Created: {live_status.get('session_rules_added_version', 0)}")
        print(f"  Skipped (No Title): {live_status.get('session_rules_skipped_no_title', 0)}")
        print(f"  Skipped (Defective/YAML Error): {live_status.get('session_rules_skipped_defective', 0)}")
        print(f"  Skipped (Other reasons/Unchanged): {live_status.get('session_rules_skipped_other', 0)}")

        print(f"\nSee '{DB_FILE}' for the database and '{RULES_DIR}/' for the rule files.")


if __name__ == '__main__':
    main()
