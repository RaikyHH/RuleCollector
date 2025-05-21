import requests
import yaml
import json
import re
import sqlite3
import hashlib
from datetime import datetime
import time
import os

CONFIG_FILE = 'config.json'
DB_FILE = 'sigma_rules.db'
REQUEST_TIMEOUT = 30 # seconds
USER_AGENT = "SigmaRuleCollector/1.0"

# --- Database Setup (unverändert) ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sigma_rules (
        id TEXT PRIMARY KEY,
        title TEXT,
        status TEXT,
        description TEXT,
        author TEXT,
        "references" TEXT,
        logsource_category TEXT,
        logsource_product TEXT,
        detection TEXT,
        falsepositives TEXT,
        level TEXT,
        tags TEXT,
        raw_rule TEXT,
        source_name TEXT,
        source_url TEXT,
        first_seen_at TIMESTAMP,
        last_updated_at TIMESTAMP,
        rule_hash TEXT
    )
    ''')
    conn.commit()
    conn.close()

# --- store_rule (unverändert, aber hier zur Vollständigkeit) ---
def store_rule(rule_data, raw_rule_content, source_name, source_url):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    current_time = datetime.now()
    rule_hash = hashlib.sha256(raw_rule_content.encode('utf-8')).hexdigest()
    rule_id = rule_data.get('id')
    if not rule_id:
        # ID aus Titel und Hash generieren, falls nicht vorhanden (nicht ideal für Sigma)
        title_slug = re.sub(r'\W+', '_', rule_data.get('title', 'untitled').lower())
        rule_id = f"generated_{title_slug}_{rule_hash[:8]}"
        print(f"⚠️ Rule from {source_url} has no ID. Generated: {rule_id}")

    logsource = rule_data.get('logsource', {})
    cursor.execute("SELECT rule_hash, first_seen_at FROM sigma_rules WHERE id = ?", (rule_id,))
    existing_rule = cursor.fetchone()

    if existing_rule:
        existing_hash, first_seen = existing_rule
        if existing_hash != rule_hash:
            print(f"🔄 Updating rule: {rule_id} ({rule_data.get('title', '')}) from {source_name}")
            cursor.execute(f'''
            UPDATE sigma_rules
            SET title=?, status=?, description=?, author=?, "references"=?,
                logsource_category=?, logsource_product=?, detection=?,
                falsepositives=?, level=?, tags=?, raw_rule=?,
                source_name=?, source_url=?, last_updated_at=?, rule_hash=?
            WHERE id=?
            ''', (
                rule_data.get('title'), rule_data.get('status'), rule_data.get('description'),
                rule_data.get('author'), json.dumps(rule_data.get('references', [])),
                logsource.get('category'), logsource.get('product'),
                json.dumps(rule_data.get('detection', {})), json.dumps(rule_data.get('falsepositives', [])),
                rule_data.get('level'), json.dumps(rule_data.get('tags', [])), raw_rule_content,
                source_name, source_url, current_time, rule_hash,
                rule_id
            ))
        # else:
            # print(f"✔️ Rule {rule_id} from {source_name} is unchanged.")
    else:
        print(f"➕ Adding new rule: {rule_id} ({rule_data.get('title', '')}) from {source_name}")
        cursor.execute(f'''
        INSERT INTO sigma_rules (
            id, title, status, description, author, "references",
            logsource_category, logsource_product, detection,
            falsepositives, level, tags, raw_rule,
            source_name, source_url, first_seen_at, last_updated_at, rule_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule_id, rule_data.get('title'), rule_data.get('status'), rule_data.get('description'),
            rule_data.get('author'), json.dumps(rule_data.get('references', [])),
            logsource.get('category'), logsource.get('product'),
            json.dumps(rule_data.get('detection', {})), json.dumps(rule_data.get('falsepositives', [])),
            rule_data.get('level'), json.dumps(rule_data.get('tags', [])), raw_rule_content,
            source_name, source_url, current_time, current_time, rule_hash
        ))
    conn.commit()
    conn.close()

# --- Fetching Logic (angepasst) ---
def fetch_url_content(url, headers): # Nimmt jetzt Header entgegen
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

# --- NEUE Hilfsfunktion für rekursives GitHub-Folder-Processing ---
def fetch_and_process_github_directory(api_dir_url, source_config_name, base_request_headers):
    """
    Recursively fetches and processes Sigma rules from a GitHub directory.
    api_dir_url: The GitHub API URL for the directory contents.
    source_config_name: The name of the source from config.json.
    base_request_headers: HTTP headers to use for requests (User-Agent, Authorization).
    """
    print(f"  Traversing GitHub directory: {api_dir_url}")
    # Kleiner Delay, um API-Limits nicht zu schnell zu erreichen
    time.sleep(0.2) # Kurzer Sleep vor jeder Directory-Auflistung

    directory_content_text = fetch_url_content(api_dir_url, base_request_headers)
    if not directory_content_text:
        return

    try:
        items = json.loads(directory_content_text)
        if not isinstance(items, list):
            # Manchmal gibt die API bei einem direkten Link zu einer Datei ein Dict zurück
            if isinstance(items, dict) and items.get('type') == 'file':
                items = [items] # Behandle es als Liste mit einem Element
            else:
                print(f"Error: GitHub API response for {api_dir_url} is not a list of items.")
                return

        for item in items:
            item_path = item.get('path', item.get('name', 'unknown_item')) # Für bessere Logs

            if item.get('type') == 'file' and item.get('name', '').endswith(('.yml', '.yaml')):
                file_download_url = item.get('download_url')
                if not file_download_url:
                    print(f"⚠️ No download_url for file {item_path} in {api_dir_url}. Skipping.")
                    continue

                print(f"    Found rule file: {item_path} (Fetching from: {file_download_url})")
                time.sleep(0.1) # Kurzer Sleep vor jedem File-Download
                file_content = fetch_url_content(file_download_url, base_request_headers)

                if file_content:
                    try:
                        rule_data = yaml.safe_load(file_content)
                        if isinstance(rule_data, dict) and rule_data.get('title'): # Grundlegende Validierung
                             store_rule(rule_data, file_content, source_config_name, file_download_url)
                        else:
                            print(f"⚠️ Content from {file_download_url} does not seem to be a valid Sigma rule (no title or not a dict). Skipping.")
                    except yaml.YAMLError as e:
                        print(f"Error parsing YAML from {file_download_url}: {e}")
                    except Exception as e:
                        print(f"An unexpected error occurred processing rule from {file_download_url}: {e}")

            elif item.get('type') == 'dir':
                # Rekursiver Aufruf für Unterverzeichnisse
                # item['url'] ist die API-URL für den Inhalt des Unterverzeichnisses
                fetch_and_process_github_directory(item['url'], source_config_name, base_request_headers)

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from GitHub API {api_dir_url}: {e}")
    except Exception as e: # Breitere Ausnahmebehandlung für unerwartete Probleme
        print(f"An unexpected error occurred while processing directory {api_dir_url}: {e}")


# --- process_source (angepasst) ---
def process_source(source_config):
    print(f"\nProcessing source: {source_config['name']} ({source_config['url']})")

    # Standard-Header für alle Anfragen
    request_headers = {'User-Agent': USER_AGENT}

    content = fetch_url_content(source_config['url'], request_headers) # fetch_url_content benötigt jetzt Header
    if not content and source_config['type'] != 'github_repo_folder': # Für GitHub Folder wird der erste 'content' direkt von der Hilfsfunktion geholt
        return

    if source_config['type'] == 'single_file_yaml':
        try:
            rule_data = yaml.safe_load(content)
            store_rule(rule_data, content, source_config['name'], source_config['url'])
        except yaml.YAMLError as e:
            print(f"Error parsing YAML from {source_config['url']}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred processing {source_config['url']}: {e}")

    elif source_config['type'] == 'raw_text_regex':
        rule_pattern_str = source_config.get('rule_regex', r"(?sm)(^title:.*?)(?=^title:|\Z)")
        rule_pattern = re.compile(rule_pattern_str)

        for match in rule_pattern.finditer(content):
            raw_rule_segment = match.group(1).strip()
            if not raw_rule_segment:
                continue
            try:
                rule_data = yaml.safe_load(raw_rule_segment)
                store_rule(rule_data, raw_rule_segment, source_config['name'], source_config['url'])
            except yaml.YAMLError as e:
                print(f"Error parsing YAML segment from {source_config['url']}: {e}\nProblematic segment:\n{raw_rule_segment[:200]}...")
            except Exception as e:
                print(f"An unexpected error occurred processing segment from {source_config['url']}: {e}")

    elif source_config['type'] == 'github_repo_folder':
        # Header für GitHub-Anfragen (kann Token enthalten)
        github_headers = {'User-Agent': USER_AGENT}
        if source_config.get('github_token'):
            github_headers['Authorization'] = f"token {source_config['github_token']}"
            print("    Using GitHub token for authentication.")
        else:
            print("    Note: No GitHub token provided. API rate limits for unauthenticated requests are stricter.")

        # Die initiale URL aus der Konfiguration ist der Startpunkt für die Rekursion
        initial_api_dir_url = source_config['url']
        fetch_and_process_github_directory(initial_api_dir_url, source_config['name'], github_headers)
    else:
        print(f"Unknown source type: {source_config['type']}")


def main():
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Sigma Rule Collector started...")
    init_db()

    if not os.path.exists(CONFIG_FILE):
        print(f"Error: Configuration file '{CONFIG_FILE}' not found.")
        return

    with open(CONFIG_FILE, 'r', encoding='utf-8') as f: # encoding='utf-8' hinzugefügt
        try:
            config_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error parsing {CONFIG_FILE}: {e}")
            return

    for source_cfg in config_data:
        if source_cfg.get("enabled", False):
            process_source(source_cfg)
        else:
            print(f"Skipping disabled source: {source_cfg['name']}")

    print(f"\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Sigma Rule Collector finished.")

if __name__ == '__main__':
    main()