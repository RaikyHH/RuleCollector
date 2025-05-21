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
USER_AGENT = "SigmaRuleCollector/1.0 (+https://github.com/your_repo_here)" # Seien Sie ein guter Netzbürger

# --- Database Setup ---
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
        references TEXT,
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

def store_rule(rule_data, raw_rule_content, source_name, source_url):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    current_time = datetime.now()
    rule_hash = hashlib.sha256(raw_rule_content.encode('utf-8')).hexdigest()

    # Extrahiere Kernfelder, falls vorhanden
    rule_id = rule_data.get('id')
    if not rule_id:
        print(f"⚠️ Rule from {source_url} has no ID. Generating one from hash.")
        # Not ideal, but better than skipping. Sigma rules *should* have IDs.
        rule_id = f"generated_{rule_hash[:16]}"


    logsource = rule_data.get('logsource', {})

    cursor.execute("SELECT rule_hash, first_seen_at FROM sigma_rules WHERE id = ?", (rule_id,))
    existing_rule = cursor.fetchone()

    if existing_rule:
        existing_hash, first_seen = existing_rule
        if existing_hash != rule_hash:
            print(f"🔄 Updating rule: {rule_id} from {source_name}")
            cursor.execute('''
            UPDATE sigma_rules
            SET title=?, status=?, description=?, author=?, references=?,
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
        else:
            # print(f"✔️ Rule {rule_id} from {source_name} is unchanged.")
            pass # No change
    else:
        print(f"➕ Adding new rule: {rule_id} from {source_name}")
        cursor.execute('''
        INSERT INTO sigma_rules (
            id, title, status, description, author, references,
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

# --- Fetching and Parsing Logic ---
def fetch_url_content(url):
    headers = {'User-Agent': USER_AGENT}
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status() # Raise HTTPError for bad responses (4XX or 5XX)
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None

def process_source(source_config):
    print(f"\nProcessing source: {source_config['name']} ({source_config['url']})")
    content = fetch_url_content(source_config['url'])
    if not content:
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
        # This regex assumes rules are separated by something like '---' or start distinctly.
        # A common pattern for Sigma rules is starting with 'title:'.
        # We use a positive lookahead to find the start of the next rule or end of string.
        # (?sm) sets DOTALL (s) and MULTILINE (m) flags.
        # ^title: matches 'title:' at the beginning of a line.
        rule_pattern = re.compile(r"(?sm)(^title:.*?)(?=^title:|\Z)")
        if 'rule_regex' in source_config: # Allow overriding regex from config
            rule_pattern = re.compile(source_config['rule_regex'])

        for match in rule_pattern.finditer(content):
            raw_rule_segment = match.group(1).strip()
            if not raw_rule_segment:
                continue
            try:
                rule_data = yaml.safe_load(raw_rule_segment)
                # Construct a more specific source_url if possible, otherwise use the base
                store_rule(rule_data, raw_rule_segment, source_config['name'], source_config['url'])
            except yaml.YAMLError as e:
                print(f"Error parsing YAML segment from {source_config['url']}: {e}\nProblematic segment:\n{raw_rule_segment[:200]}...")
            except Exception as e:
                print(f"An unexpected error occurred processing segment from {source_config['url']}: {e}")


    elif source_config['type'] == 'github_repo_folder':
        try:
            api_response = json.loads(content) # Content is the JSON from GitHub API
            if not isinstance(api_response, list):
                print(f"Error: GitHub API response for {source_config['url']} is not a list.")
                return

            for item in api_response:
                if item['type'] == 'file' and item['name'].endswith(('.yml', '.yaml')):
                    file_url = item.get('download_url') # This is the direct raw content URL
                    if not file_url: # Fallback if download_url is not present
                        # Construct raw URL using base_raw_url and item['path']
                        # Example item['path']: "rules/windows/process_creation/proc_creation_win_explorer_run_key_access.yml"
                        if 'base_raw_url' in source_config and 'path' in item:
                             file_url = source_config['base_raw_url'] + item['path']
                        else:
                            print(f"⚠️ Cannot determine download URL for {item['name']} in {source_config['name']}. Skipping.")
                            continue

                    print(f"  Fetching from GitHub folder: {item['name']}")
                    file_content = fetch_url_content(file_url)
                    if file_content:
                        try:
                            rule_data = yaml.safe_load(file_content)
                            store_rule(rule_data, file_content, source_config['name'], file_url)
                        except yaml.YAMLError as e:
                            print(f"Error parsing YAML from {file_url}: {e}")
                        except Exception as e:
                            print(f"An unexpected error occurred processing {file_url}: {e}")
                    time.sleep(0.5) # Be polite to APIs
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from GitHub API {source_config['url']}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred processing GitHub folder {source_config['url']}: {e}")

    else:
        print(f"Unknown source type: {source_config['type']}")


def main():
    print("Sigma Rule Collector started...")
    init_db()

    if not os.path.exists(CONFIG_FILE):
        print(f"Error: Configuration file '{CONFIG_FILE}' not found.")
        return

    with open(CONFIG_FILE, 'r') as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error parsing {CONFIG_FILE}: {e}")
            return

    for source_config in config:
        if source_config.get("enabled", False):
            process_source(source_config)
        else:
            print(f"Skipping disabled source: {source_config['name']}")

    print("\nSigma Rule Collector finished.")

if __name__ == '__main__':
    main()