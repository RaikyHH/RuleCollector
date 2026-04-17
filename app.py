from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import sqlite3
import json
import os
import re
import tempfile
import threading
import time
import uuid
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

app = Flask(__name__)
_DATA_DIR = os.environ.get('DATA_DIR', os.path.dirname(os.path.abspath(__file__)))
DB_FILE = os.path.join(_DATA_DIR, 'sigma_rules.db')
CONFIG_FILE = os.path.join(_DATA_DIR, 'config.json')
FEATURES_FILE = os.path.join(_DATA_DIR, 'features.json')

# Genome similarity cache (module-level)
_genome_cache = {'index': None, 'count': -1}

DEFAULT_FEATURES = {'tide_chart': True, 'decay_scoring': True}

# MITRE ATT&CK tactics order for heatmap
MITRE_TACTICS = [
    ('reconnaissance',      'Recon'),
    ('resource-development','ResDev'),
    ('initial-access',      'InitAcc'),
    ('execution',           'Exec'),
    ('persistence',         'Persist'),
    ('privilege-escalation','PrivEsc'),
    ('defense-evasion',     'DefEva'),
    ('credential-access',   'CredAcc'),
    ('discovery',           'Discov'),
    ('lateral-movement',    'LatMov'),
    ('collection',          'Collect'),
    ('command-and-control', 'C2'),
    ('exfiltration',        'Exfil'),
    ('impact',              'Impact'),
]


def _load_config():
    if not os.path.exists(CONFIG_FILE):
        return []
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _load_features():
    if not os.path.exists(FEATURES_FILE):
        try:
            with open(FEATURES_FILE, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_FEATURES, f, indent=2)
        except OSError:
            pass
        return dict(DEFAULT_FEATURES)
    try:
        with open(FEATURES_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            merged = dict(DEFAULT_FEATURES)
            if isinstance(data, dict):
                merged.update(data)
            return merged
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_FEATURES)


def _save_config(sources):
    # atomic write - avoid corrupting the file if something blows up mid-write
    dir_name = os.path.dirname(os.path.abspath(CONFIG_FILE)) or '.'
    fd, tmp_path = tempfile.mkstemp(prefix='.config_', suffix='.tmp', dir=dir_name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(sources, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, CONFIG_FILE)
    except Exception:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise


# ---------------------------------------------------------------------------
# Sync job registry  (in-memory, single-process)
# ---------------------------------------------------------------------------
# Each job is a dict:  { 'status': 'running'|'done'|'error',
#                        'events': [ {source, state, counts} … ],
#                        'totals': {…},
#                        'started_at': float, 'finished_at': float|None }
_sync_jobs: dict[str, dict] = {}
_sync_jobs_lock = threading.Lock()


def _new_job(source_indices: list[int] | None) -> str:
    job_id = str(uuid.uuid4())
    with _sync_jobs_lock:
        _sync_jobs[job_id] = {
            'status': 'running',
            'source_indices': source_indices,
            'events': [],
            'totals': {},
            'started_at': time.time(),
            'finished_at': None,
        }
    return job_id


def _job_append(job_id: str, event: dict):
    with _sync_jobs_lock:
        if job_id in _sync_jobs:
            _sync_jobs[job_id]['events'].append(event)


def _job_finish(job_id: str, totals: dict, status: str = 'done'):
    with _sync_jobs_lock:
        if job_id in _sync_jobs:
            _sync_jobs[job_id]['status'] = status
            _sync_jobs[job_id]['totals'] = totals
            _sync_jobs[job_id]['finished_at'] = time.time()


def _ensure_rule_authored_at_column():
    """One-time migration: add rule_authored_at column and backfill from raw_rule YAML."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        cols = [r[1] for r in conn.execute('PRAGMA table_info(sigma_rules)').fetchall()]
        if 'rule_authored_at' not in cols:
            conn.execute('ALTER TABLE sigma_rules ADD COLUMN rule_authored_at TEXT')
            conn.commit()

        # Backfill where rule_authored_at is NULL and raw_rule exists
        rows = conn.execute(
            "SELECT id, raw_rule FROM sigma_rules WHERE rule_authored_at IS NULL AND raw_rule IS NOT NULL"
        ).fetchall()
        updated = 0
        for row in rows:
            raw = row['raw_rule'] or ''
            # Extract modified: or date: from YAML text (no full YAML parse needed)
            val = None
            m = re.search(r'^modified:\s*([^\n]+)', raw, re.MULTILINE)
            if m:
                val = m.group(1).strip()
            else:
                m2 = re.search(r'^date:\s*([^\n]+)', raw, re.MULTILINE)
                if m2:
                    val = m2.group(1).strip()
            if val:
                # Normalize: YYYY/MM/DD → YYYY-MM-DD
                val = val.replace('/', '-')
                if re.match(r'^\d{4}-\d{2}-\d{2}', val):
                    conn.execute(
                        "UPDATE sigma_rules SET rule_authored_at = ? WHERE id = ?",
                        (val[:10], row['id'])
                    )
                    updated += 1
        if updated:
            conn.commit()
    finally:
        conn.close()


def _ensure_sigmahq_category_columns():
    """One-time migration: add sigmahq_category_1/2 and sigmahq_path columns, backfill from source_url."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        cols = [r[1] for r in conn.execute('PRAGMA table_info(sigma_rules)').fetchall()]
        changed = False
        if 'sigmahq_category_1' not in cols:
            conn.execute('ALTER TABLE sigma_rules ADD COLUMN sigmahq_category_1 TEXT')
            changed = True
        if 'sigmahq_category_2' not in cols:
            conn.execute('ALTER TABLE sigma_rules ADD COLUMN sigmahq_category_2 TEXT')
            changed = True
        if 'sigmahq_path' not in cols:
            conn.execute('ALTER TABLE sigma_rules ADD COLUMN sigmahq_path TEXT')
            changed = True
        if changed:
            conn.commit()

        # Backfill all SigmaHQ rules that are missing the path column
        rows = conn.execute(
            "SELECT id, source_url FROM sigma_rules WHERE source_url LIKE '%SigmaHQ/sigma%' AND (sigmahq_path IS NULL OR sigmahq_category_1 IS NULL)"
        ).fetchall()
        updated = 0
        for row in rows:
            path = _extract_sigmahq_path(row['source_url'])
            if path:
                cat1 = path[0]
                cat2 = path[1] if len(path) >= 2 else None
                conn.execute(
                    "UPDATE sigma_rules SET sigmahq_category_1=?, sigmahq_category_2=?, sigmahq_path=? WHERE id=?",
                    (cat1, cat2, json.dumps(path), row['id'])
                )
                updated += 1
        if updated:
            conn.commit()
    finally:
        conn.close()


def _extract_sigmahq_categories(source_url: str):
    """
    Extract (cat1, cat2) from a SigmaHQ raw URL for backward-compat columns.
    Use _extract_sigmahq_path() for the full path.
    """
    path = _extract_sigmahq_path(source_url)
    cat1 = path[0] if len(path) >= 1 else None
    cat2 = path[1] if len(path) >= 2 else None
    return cat1, cat2


def _extract_sigmahq_path(source_url: str) -> list:
    """
    Extract all folder segments (excluding the filename) from a SigmaHQ URL,
    title-cased with underscores replaced by spaces.

    E.g. .../rules/windows/file/file_access/rule.yml → ['Windows', 'File', 'File Access']
    Returns [] if URL does not match or has no folder segments.
    """
    if not source_url:
        return []
    m = re.search(r'/rules/(.+)', source_url)
    if not m:
        return []
    # Drop the last segment (the filename)
    parts = m.group(1).split('/')
    if len(parts) < 2:
        return []
    folder_parts = parts[:-1]  # everything except the filename
    return [p.replace('_', ' ').title() for p in folder_parts]


def _ensure_sync_history_table():
    conn = sqlite3.connect(DB_FILE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sync_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT,
            started_at TEXT,
            finished_at TEXT,
            status TEXT,
            rules_added INTEGER DEFAULT 0,
            rules_updated INTEGER DEFAULT 0,
            rules_unchanged INTEGER DEFAULT 0,
            rules_versioned INTEGER DEFAULT 0,
            rules_skipped INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()


def _insert_sync_history(source_name: str, started_at: float, finished_at: float,
                         status: str, counts: dict):
    try:
        _ensure_sync_history_table()
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            '''INSERT INTO sync_history
               (source_name, started_at, finished_at, status,
                rules_added, rules_updated, rules_unchanged, rules_versioned, rules_skipped)
               VALUES (?,?,?,?,?,?,?,?,?)''',
            (
                source_name,
                datetime.fromtimestamp(started_at).isoformat(),
                datetime.fromtimestamp(finished_at).isoformat(),
                status,
                counts.get('session_rules_added_new', 0),
                counts.get('session_rules_updated_content', 0),
                counts.get('session_rules_updated_ts', 0),
                counts.get('session_rules_added_version', 0),
                counts.get('session_rules_skipped_defective', 0)
                    + counts.get('session_rules_skipped_no_title', 0)
                    + counts.get('session_rules_skipped_other', 0),
            )
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # history is nice-to-have, don't crash the sync


def _run_sync(job_id: str, sources: list[dict]):
    """Run collector logic in a background thread, posting events to the job."""
    import collector as col

    overall_start = time.time()
    live_status = {
        'session_rules_processed': 0, 'session_rules_added_new': 0,
        'session_rules_updated_content': 0, 'session_rules_updated_ts': 0,
        'session_rules_added_version': 0, 'session_rules_skipped_no_title': 0,
        'session_rules_skipped_other': 0, 'session_rules_skipped_defective': 0,
    }

    try:
        col.init_db(overall_start)
        _ensure_sync_history_table()
        for src in sources:
            src_start = time.time()
            _job_append(job_id, {
                'type': 'source_start',
                'source': src['name'],
            })
            snap_before = dict(live_status)
            try:
                col.process_source(src, live_status, overall_start)
                delta = {k: live_status[k] - snap_before.get(k, 0) for k in live_status}
                _job_append(job_id, {
                    'type': 'source_done',
                    'source': src['name'],
                    'counts': delta,
                })
                _insert_sync_history(src['name'], src_start, time.time(), 'done', delta)
            except Exception as exc:
                _job_append(job_id, {
                    'type': 'source_error',
                    'source': src['name'],
                    'error': str(exc),
                })
                _insert_sync_history(src['name'], src_start, time.time(), 'error', {})
        _job_finish(job_id, live_status, 'done')
    except Exception as exc:
        _job_append(job_id, {'type': 'fatal', 'error': str(exc)})
        _job_finish(job_id, live_status, 'error')


def _get_shared_token(sources):
    # Env var takes precedence over per-source config (useful in Docker/CI)
    env_token = os.environ.get('GITHUB_TOKEN', '').strip()
    if env_token:
        return env_token
    for src in sources:
        token = src.get('github_token')
        if token:
            return token
    return ''


def _parse_github_url(repo_url):
    """Extract (owner, repo) from any common github URL style."""
    if not repo_url:
        return None, None
    url = repo_url.strip()

    # strip possible "git@github.com:owner/repo.git" style
    ssh_match = re.match(r'^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?/?$', url)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2)

    # add scheme if user typed "github.com/..."
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed = urlparse(url)
    except ValueError:
        return None, None

    if 'github.com' not in (parsed.netloc or '').lower():
        return None, None

    parts = [p for p in parsed.path.split('/') if p]
    if len(parts) < 2:
        return None, None

    owner = parts[0]
    repo = parts[1]
    if repo.endswith('.git'):
        repo = repo[:-4]
    return owner, repo


def _github_get(url, token=None):
    req = Request(url, headers={
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'RuleCollector'
    })
    if token:
        req.add_header('Authorization', f'token {token}')
    with urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode('utf-8'))


def _discover_sigma_folder(owner, repo, token=None):
    """
    Walk the repo tree, find the top-level directory with the most .yml files.
    Prefer paths that contain sigma/rule/detect if any exist.
    """
    meta = _github_get(f'https://api.github.com/repos/{owner}/{repo}', token)
    default_branch = meta.get('default_branch', 'HEAD')

    tree = _github_get(
        f'https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1',
        token
    )

    entries = tree.get('tree', []) or []
    yaml_files = [
        e['path'] for e in entries
        if e.get('type') == 'blob' and e.get('path', '').lower().endswith(('.yml', '.yaml'))
    ]

    if not yaml_files:
        return {
            'meta': meta,
            'folder': '',
            'estimated_rules': 0,
            'truncated': tree.get('truncated', False),
        }

    # Count yml files per top-level directory
    top_counts = Counter()
    for path in yaml_files:
        segments = path.split('/')
        if len(segments) > 1:
            top_counts[segments[0]] += 1

    # Prefer folders whose name hints at sigma content
    keywords = ('sigma', 'rule', 'detect')
    hinted = {k: v for k, v in top_counts.items() if any(kw in k.lower() for kw in keywords)}

    if hinted:
        best_folder = max(hinted.items(), key=lambda kv: kv[1])[0]
    elif top_counts:
        best_folder = max(top_counts.items(), key=lambda kv: kv[1])[0]
    else:
        best_folder = ''

    # Count yml files under the chosen folder (or at root if none picked)
    if best_folder:
        prefix = best_folder + '/'
        estimated = sum(1 for p in yaml_files if p.startswith(prefix))
    else:
        estimated = sum(1 for p in yaml_files if '/' not in p) or len(yaml_files)

    return {
        'meta': meta,
        'folder': best_folder,
        'estimated_rules': estimated,
        'truncated': tree.get('truncated', False),
    }

def _ensure_schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sigma_rules (
            id TEXT PRIMARY KEY,
            title TEXT,
            status TEXT,
            level TEXT,
            description TEXT,
            author TEXT,
            date TEXT,
            tags TEXT,
            logsource TEXT,
            logsource_product TEXT,
            logsource_category TEXT,
            logsource_service TEXT,
            detection TEXT,
            references TEXT,
            falsepositives TEXT,
            raw_rule TEXT,
            source_name TEXT,
            source_url TEXT,
            first_seen_at TEXT,
            last_updated_at TEXT,
            rule_hash TEXT,
            sigmahq_path TEXT,
            sigmahq_category_1 TEXT,
            sigmahq_category_2 TEXT,
            rule_authored_at TEXT
        )
    """)
    conn.commit()


def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn)
    return conn


@app.context_processor
def inject_features():
    return {'features': _load_features()}

@app.template_filter('tojson_rule')
def tojson_rule_filter(row):
    """Serialize a sqlite3.Row (selected_rule) to a JSON string safe for embedding in <script>."""
    if row is None:
        return 'null'
    d = dict(row)
    # Parse JSON columns so the client gets real arrays/objects
    for col in ('tags', 'references', 'falsepositives', 'detection'):
        if d.get(col):
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                pass
    # Escape </script> sequences to prevent XSS when embedding in a <script> tag
    return json.dumps(d, ensure_ascii=False).replace('</', '<\\/')


@app.template_filter('fromjson')
def fromjson_filter(value):
    if not value:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value

@app.template_filter('pretty_json_format')
def pretty_json_format_filter(value):
    if value is None:
        return "N/A"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return value
    try:
        return json.dumps(value, indent=2, ensure_ascii=False)
    except TypeError:
        return str(value)

@app.template_filter('format_datetime')
def format_datetime_filter(value):
    if not value:
        return "N/A"
    if isinstance(value, str):
        try:
            dt_obj = datetime.fromisoformat(value.split('.')[0])
            return dt_obj.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    elif isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    return value

def _get_suppressed_version_ids(cursor) -> set:
    """
    Return the set of rule IDs that are older siblings in a version family.
    A version family is defined by sharing the same base title (title with trailing 'v2', 'v3'… stripped).
    For each family, only the rule with the *latest* first_seen_at is shown; all others are suppressed.
    """
    rows = cursor.execute(
        "SELECT id, title, first_seen_at FROM sigma_rules WHERE title IS NOT NULL"
    ).fetchall()

    _v_strip = re.compile(r'\s+v\d+(\.\d+)*\s*$', re.IGNORECASE)

    # Group by normalized base title
    from collections import defaultdict
    families: dict[str, list] = defaultdict(list)
    for row in rows:
        base = _v_strip.sub('', row['title']).strip().lower()
        families[base].append({'id': row['id'], 'title': row['title'], 'first_seen_at': row['first_seen_at'] or ''})

    suppressed: set = set()
    for base, members in families.items():
        # Only suppress if at least one member has a version suffix (i.e. it's actually a versioned family)
        has_versioned = any(
            _v_strip.sub('', m['title']).strip().lower() != m['title'].strip().lower()
            for m in members
        )
        if not has_versioned or len(members) < 2:
            continue
        # Keep the member with the latest first_seen_at (lexicographic ISO comparison works here)
        best = max(members, key=lambda m: m['first_seen_at'])
        for m in members:
            if m['id'] != best['id']:
                suppressed.add(m['id'])

    return suppressed


def _get_filtered_rules(cursor, search_query, mitre_id_query, level_query, status_query,
                         product_query='', category_query='', source_query='', author_query='',
                         show_decayed=False, features=None):
    """
    show_decayed=False (default): hide rules whose author date exceeds decay warn threshold.
    show_decayed=True: include decayed rules in the results.
    """
    query_conditions = []
    params = []

    if search_query:
        query_conditions.append("(title LIKE ? OR description LIKE ? OR id LIKE ? OR raw_rule LIKE ?)")
        params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])
    if mitre_id_query:
        query_conditions.append("tags LIKE ?")
        params.append(f"%{mitre_id_query}%")
    if level_query:
        query_conditions.append("level = ?")
        params.append(level_query)
    if status_query:
        query_conditions.append("status = ?")
        params.append(status_query)
    if product_query:
        query_conditions.append("logsource_product LIKE ?")
        params.append(f"%{product_query}%")
    if category_query:
        query_conditions.append("logsource_category LIKE ?")
        params.append(f"%{category_query}%")
    if source_query:
        query_conditions.append("source_name = ?")
        params.append(source_query)
    if author_query:
        query_conditions.append("author LIKE ?")
        params.append(f"%{author_query}%")

    # By default, exclude rules that have passed the decay warn threshold.
    # show_decayed=True disables this exclusion.
    if not show_decayed:
        feat = features or _load_features()
        hide_days = int(feat.get('decay_hide_days', 730))
        # Only exclude when we have a reliable date; rules without rule_authored_at are kept.
        query_conditions.append(
            "(rule_authored_at IS NULL OR julianday('now') - julianday(rule_authored_at) < ?)"
        )
        params.append(hide_days)

    base_query = "SELECT id, title, level, status, logsource_product, last_updated_at, source_name, sigmahq_category_1, sigmahq_category_2, sigmahq_path FROM sigma_rules"
    if query_conditions:
        query = f"{base_query} WHERE {' AND '.join(query_conditions)} ORDER BY title ASC"
    else:
        query = f"{base_query} ORDER BY title ASC"

    all_rules = cursor.execute(query, tuple(params)).fetchall()

    # Suppress older version siblings — they remain accessible via the "Other Versions" chips
    suppressed = _get_suppressed_version_ids(cursor)
    if suppressed:
        all_rules = [r for r in all_rules if r['id'] not in suppressed]

    return all_rules


SIGMAHQ_SOURCE_NAME = 'SigmaHQ Rules (Full Repo)'


def _insert_into_tree(node: dict, path_segments: list, rule):
    """
    Recursively insert a rule into a nested tree dict.

    node structure:
      { '_rules': [...],           # rules at this exact level
        'children': {              # ordered dict of child node name → node
            'Child Name': { '_rules': [...], 'children': {...} },
            ...
        }
      }
    path_segments is the remaining path to traverse (already title-cased).
    """
    if not path_segments:
        node['_rules'].append(rule)
        return
    child_name = path_segments[0]
    if child_name not in node['children']:
        node['children'][child_name] = {'_rules': [], 'children': {}}
    _insert_into_tree(node['children'][child_name], path_segments[1:], rule)


def _tree_node_to_list(name: str, node: dict) -> dict:
    """Convert a tree node dict into a serialisable structure for the template."""
    children = [
        _tree_node_to_list(child_name, child_node)
        for child_name, child_node in sorted(node['children'].items())
    ]
    rule_count = len(node['_rules']) + sum(c['rule_count'] for c in children)
    return {
        'name': name,
        'rules': node['_rules'],
        'children': children,
        'rule_count': rule_count,
    }


def _build_grouped_rules(rules):
    """
    Build a grouped structure for the sidebar.

    SigmaHQ rules are organised into a recursive category tree derived from
    their URL path (e.g. windows/file/file_access → ['Windows','File','File Access']).
    Other repos get a flat list of rules (no sub-grouping).

    Returns a list of group dicts, SigmaHQ always first:
      [
        { 'source': '…', 'is_sigmahq': True, 'tree': <tree node>, 'rule_count': N },
        { 'source': '…', 'is_sigmahq': False, 'rules': [...], 'rule_count': N },
        …
      ]
    """
    sigmahq_rules = []
    other_repos = {}  # source_name → list of rules

    for r in rules:
        sn = r['source_name'] or 'Unknown'
        if sn == SIGMAHQ_SOURCE_NAME:
            sigmahq_rules.append(r)
        else:
            other_repos.setdefault(sn, []).append(r)

    groups = []

    # --- SigmaHQ group with recursive category tree ---
    if sigmahq_rules:
        root = {'_rules': [], 'children': {}}
        for r in sigmahq_rules:
            raw_path = r['sigmahq_path']
            if raw_path:
                try:
                    path = json.loads(raw_path)
                except (json.JSONDecodeError, TypeError):
                    path = []
            else:
                # Fallback: use the two legacy columns
                c1 = r['sigmahq_category_1']
                c2 = r['sigmahq_category_2']
                path = [x for x in [c1, c2] if x]
            if not path:
                path = ['(Uncategorized)']
            _insert_into_tree(root, path, r)

        tree = _tree_node_to_list('__root__', root)
        groups.append({
            'source': SIGMAHQ_SOURCE_NAME,
            'is_sigmahq': True,
            'tree': tree,
            'rule_count': len(sigmahq_rules),
        })

    # --- Other repos (flat) ---
    for sn in sorted(other_repos.keys()):
        groups.append({
            'source': sn,
            'is_sigmahq': False,
            'rules': other_repos[sn],
            'rule_count': len(other_repos[sn]),
        })

    return groups


@app.route('/')
def index():
    search_query    = request.args.get('search',      '').strip()
    mitre_id_query  = request.args.get('mitre_id',    '').strip()
    level_query     = request.args.get('level',       '').strip()
    status_query    = request.args.get('status',      '').strip()
    product_query   = request.args.get('product',     '').strip()
    category_query  = request.args.get('category',    '').strip()
    source_query    = request.args.get('source',      '').strip()
    author_query    = request.args.get('author',      '').strip()
    show_decayed    = request.args.get('show_decayed','') == '1'

    features = _load_features()
    conn = get_db_connection()
    cursor = conn.cursor()

    rules = _get_filtered_rules(cursor, search_query, mitre_id_query, level_query, status_query,
                                product_query, category_query, source_query, author_query,
                                show_decayed, features)

    distinct_sources = [r[0] for r in cursor.execute(
        "SELECT DISTINCT source_name FROM sigma_rules WHERE source_name IS NOT NULL AND source_name != '' ORDER BY source_name"
    ).fetchall()]
    rule_count = cursor.execute("SELECT COUNT(*) FROM sigma_rules").fetchone()[0]

    conn.close()

    grouped_rules = _build_grouped_rules(rules)

    return render_template('index.html',
                           rules=rules,
                           grouped_rules=grouped_rules,
                           search_query=search_query,
                           mitre_id_query=mitre_id_query,
                           level_query=level_query,
                           status_query=status_query,
                           product_query=product_query,
                           category_query=category_query,
                           source_query=source_query,
                           author_query=author_query,
                           show_decayed=show_decayed,
                           distinct_sources=distinct_sources,
                           rule_count=rule_count,
                           rule_versions=[],
                           selected_rule_id=None)

@app.route('/rule/<rule_id>')
def get_rule_details_page(rule_id):
    search_query    = request.args.get('search',      '').strip()
    mitre_id_query  = request.args.get('mitre_id',    '').strip()
    level_query     = request.args.get('level',       '').strip()
    status_query    = request.args.get('status',      '').strip()
    product_query   = request.args.get('product',     '').strip()
    category_query  = request.args.get('category',    '').strip()
    source_query    = request.args.get('source',      '').strip()
    author_query    = request.args.get('author',      '').strip()
    show_decayed    = request.args.get('show_decayed','') == '1'

    features = _load_features()
    conn = get_db_connection()
    cursor = conn.cursor()

    rules_list = _get_filtered_rules(cursor, search_query, mitre_id_query, level_query, status_query,
                                     product_query, category_query, source_query, author_query,
                                     show_decayed, features)
    selected_rule = cursor.execute("SELECT * FROM sigma_rules WHERE id = ?", (rule_id,)).fetchone()

    distinct_sources = [r[0] for r in cursor.execute(
        "SELECT DISTINCT source_name FROM sigma_rules WHERE source_name IS NOT NULL AND source_name != '' ORDER BY source_name"
    ).fetchall()]
    rule_count = cursor.execute("SELECT COUNT(*) FROM sigma_rules").fetchone()[0]

    # Feature #9: find related versions (same base title, different id)
    rule_versions = []
    if selected_rule:
        base_title = re.sub(r'\s+v\d+(\.\d+)*\s*$', '', selected_rule['title'] or '', flags=re.IGNORECASE).strip()
        if base_title:
            related = cursor.execute(
                "SELECT id, title, first_seen_at FROM sigma_rules WHERE title LIKE ? AND id != ? ORDER BY first_seen_at ASC",
                (f"{base_title}%", rule_id)
            ).fetchall()
            rule_versions = [
                r for r in related
                if re.sub(r'\s+v\d+(\.\d+)*\s*$', '', r['title'] or '', flags=re.IGNORECASE).strip().lower() == base_title.lower()
            ]

    conn.close()

    grouped_rules = _build_grouped_rules(rules_list)

    shared_ctx = dict(
        search_query=search_query, mitre_id_query=mitre_id_query,
        level_query=level_query, status_query=status_query,
        product_query=product_query, category_query=category_query,
        source_query=source_query, author_query=author_query,
        show_decayed=show_decayed,
        distinct_sources=distinct_sources, rule_count=rule_count,
        grouped_rules=grouped_rules,
    )

    if not selected_rule:
        return render_template('index.html',
                               rules=rules_list, error_message="Regel nicht gefunden.",
                               selected_rule_id=None, rule_versions=[],
                               **shared_ctx), 404

    return render_template('index.html',
                           rules=rules_list, selected_rule=selected_rule,
                           selected_rule_id=rule_id, rule_versions=rule_versions,
                           **shared_ctx)

@app.route('/api/rule/<rule_id>')
def api_get_rule(rule_id):
    conn = get_db_connection()
    rule = conn.execute('SELECT * FROM sigma_rules WHERE id = ?', (rule_id,)).fetchone()
    conn.close()

    if rule is None:
        return jsonify({'error': 'Rule not found'}), 404

    rule_dict = dict(rule)
    for key in ('references', 'falsepositives', 'tags'):
        val = rule_dict.get(key)
        if val is None:
            rule_dict[key] = []
            continue
        if isinstance(val, list):
            continue
        try:
            parsed = json.loads(val)
            rule_dict[key] = parsed if isinstance(parsed, list) else [parsed]
        except (json.JSONDecodeError, TypeError):
            # Treat bare string as a single-element list
            rule_dict[key] = [val] if val else []
    for key in ('detection',):
        val = rule_dict.get(key)
        if val and isinstance(val, str):
            try:
                rule_dict[key] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                pass

    return jsonify(rule_dict)


@app.route('/api/rule_versions')
def api_rule_versions():
    """Return sibling versioned rules sharing the same base title."""
    base_title = request.args.get('title', '').strip()
    exclude_id = request.args.get('exclude', '').strip()
    if not base_title:
        return jsonify([])

    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, title, first_seen_at FROM sigma_rules WHERE title LIKE ? AND id != ? ORDER BY first_seen_at ASC",
        (f"{base_title}%", exclude_id)
    ).fetchall()
    conn.close()

    results = [
        {'id': r['id'], 'title': r['title']}
        for r in rows
        if re.sub(r'\s+v\d+(\.\d+)*\s*$', '', r['title'] or '', flags=re.IGNORECASE).strip().lower()
           == base_title.lower()
    ]
    return jsonify(results)

def _load_sync_state(source_name: str) -> dict:
    """Load the sync_state JSON for a given source name, or return {}."""
    state_dir = os.path.join(_DATA_DIR, 'sync_state')
    safe_name = re.sub(r'\W', '_', source_name) + '.json'
    path = os.path.join(state_dir, safe_name)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


@app.route('/sources')
def sources_page():
    sources = _load_config()
    # Per-source rule counts from DB
    rule_counts = {}
    total_rules = 0
    if os.path.exists(DB_FILE):
        try:
            conn = get_db_connection()
            rows = conn.execute(
                "SELECT source_name, COUNT(*) as cnt FROM sigma_rules GROUP BY source_name"
            ).fetchall()
            conn.close()
            for r in rows:
                sn = r['source_name'] or ''
                rule_counts[sn] = r['cnt']
                total_rules += r['cnt']
        except Exception:
            pass

    # Per-source file counts from sync state files (total files seen in repo)
    state_file_counts = {}
    state_last_sync = {}
    for src in sources:
        state = _load_sync_state(src['name'])
        if state:
            state_file_counts[src['name']] = len(state.get('files', {}))
            state_last_sync[src['name']] = state.get('last_sync', '')

    return render_template('sources.html', sources=sources,
                           rule_counts=rule_counts, total_rules=total_rules,
                           state_file_counts=state_file_counts,
                           state_last_sync=state_last_sync,
                           sigmahq_source_name=SIGMAHQ_SOURCE_NAME)


@app.route('/api/sources/discover', methods=['POST'])
def api_sources_discover():
    payload = request.get_json(silent=True) or {}
    repo_url = (payload.get('repo_url') or '').strip()
    if not repo_url:
        return jsonify({'error': 'Please provide a GitHub repository URL.'}), 400

    owner, repo = _parse_github_url(repo_url)
    if not owner or not repo:
        return jsonify({'error': 'Could not parse owner/repo from the provided URL.'}), 400

    # Token priority: explicit from UI > shared token from config
    token = (payload.get('github_token') or '').strip() or _get_shared_token(_load_config())

    try:
        info = _discover_sigma_folder(owner, repo, token)
    except HTTPError as e:
        if e.code == 404:
            return jsonify({'error': f'Repository {owner}/{repo} not found (404).'}), 404
        if e.code in (401, 403):
            if token:
                # Token was rejected — retry without it (works for public repos)
                try:
                    info = _discover_sigma_folder(owner, repo, token=None)
                    token = ''  # don't propagate the bad token to the saved entry
                except HTTPError as e2:
                    if e2.code == 404:
                        return jsonify({'error': f'Repository {owner}/{repo} not found (404).'}), 404
                    return jsonify({'error': f'GitHub rejected the request ({e2.code}). The repo may be private or the token is invalid.'}), 502
                except Exception as e2:
                    return jsonify({'error': f'Discovery failed: {e2}'}), 500
            else:
                return jsonify({'error': f'GitHub rejected the request ({e.code}). The repo may be private — provide a valid token.'}), 502
        else:
            return jsonify({'error': f'GitHub API error: {e.code} {e.reason}'}), 502
    except URLError as e:
        return jsonify({'error': f'Network error talking to GitHub: {e.reason}'}), 502
    except Exception as e:
        return jsonify({'error': f'Discovery failed: {e}'}), 500

    meta = info['meta']
    owner_name = (meta.get('owner') or {}).get('login') or owner
    repo_name = meta.get('name') or repo
    folder = info['folder']

    if folder:
        api_url = f'https://api.github.com/repos/{owner}/{repo}/contents/{folder}'
    else:
        api_url = f'https://api.github.com/repos/{owner}/{repo}/contents/'

    pretty_name = f'{owner_name} {repo_name} Sigma Rules'

    return jsonify({
        'name': pretty_name,
        'url': api_url,
        'type': 'github_repo_folder',
        'estimated_rules': info['estimated_rules'],
        'folder_path': folder or '(repository root)',
        'truncated': info.get('truncated', False),
        'description': meta.get('description') or '',
    })


@app.route('/api/sources/add', methods=['POST'])
def api_sources_add():
    payload = request.get_json(silent=True) or {}
    name = (payload.get('name') or '').strip()
    url = (payload.get('url') or '').strip()
    src_type = (payload.get('type') or 'github_repo_folder').strip()
    enabled = bool(payload.get('enabled', True))

    if not name or not url:
        return jsonify({'error': 'Name and URL are required.'}), 400

    sources = _load_config()

    # Don't add the same URL twice - silently reject
    if any(s.get('url', '').rstrip('/') == url.rstrip('/') for s in sources):
        return jsonify({'error': 'A source with this URL already exists.'}), 409

    new_entry = {
        'name': name,
        'url': url,
        'type': src_type,
        'enabled': enabled,
        'github_token': _get_shared_token(sources),
    }
    sources.append(new_entry)

    try:
        _save_config(sources)
    except OSError as e:
        return jsonify({'error': f'Failed to write config: {e}'}), 500

    return jsonify({'success': True, 'source': new_entry})


@app.route('/api/sources/toggle', methods=['POST'])
def api_sources_toggle():
    payload = request.get_json(silent=True) or {}
    try:
        idx = int(payload.get('index'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid index.'}), 400
    enabled = bool(payload.get('enabled'))

    sources = _load_config()
    if idx < 0 or idx >= len(sources):
        return jsonify({'error': 'Index out of range.'}), 404

    sources[idx]['enabled'] = enabled
    try:
        _save_config(sources)
    except OSError as e:
        return jsonify({'error': f'Failed to write config: {e}'}), 500

    return jsonify({'success': True})


@app.route('/api/sources/delete', methods=['DELETE'])
def api_sources_delete():
    payload = request.get_json(silent=True) or {}
    try:
        idx = int(payload.get('index'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid index.'}), 400

    sources = _load_config()
    if idx < 0 or idx >= len(sources):
        return jsonify({'error': 'Index out of range.'}), 404

    removed = sources.pop(idx)
    try:
        _save_config(sources)
    except OSError as e:
        return jsonify({'error': f'Failed to write config: {e}'}), 500

    return jsonify({'success': True, 'removed': removed.get('name', '')})


@app.route('/api/sources/token', methods=['POST'])
def api_sources_token():
    """Replace the github_token on all sources at once."""
    payload = request.get_json(silent=True) or {}
    token = (payload.get('github_token') or '').strip()
    # allow empty string to clear the token
    sources = _load_config()
    for src in sources:
        src['github_token'] = token
    try:
        _save_config(sources)
    except OSError as e:
        return jsonify({'error': f'Failed to write config: {e}'}), 500
    return jsonify({'success': True, 'updated': len(sources)})


@app.route('/api/sources/sync', methods=['POST'])
def api_sources_sync():
    """Start a sync job. Body: {"indices": [0,1,…]} or {} for all enabled."""
    payload = request.get_json(silent=True) or {}
    indices = payload.get('indices')  # None means "all enabled"

    all_sources = _load_config()
    if indices is not None:
        try:
            sources_to_sync = [all_sources[i] for i in indices if 0 <= i < len(all_sources)]
        except (TypeError, KeyError):
            return jsonify({'error': 'Invalid indices.'}), 400
    else:
        sources_to_sync = [s for s in all_sources if s.get('enabled')]

    if not sources_to_sync:
        return jsonify({'error': 'No enabled sources to sync.'}), 400

    job_id = _new_job(indices)
    t = threading.Thread(target=_run_sync, args=(job_id, sources_to_sync), daemon=True)
    t.start()
    return jsonify({'job_id': job_id})


@app.route('/api/sync/stream/<job_id>')
def api_sync_stream(job_id: str):
    """SSE stream that delivers events for a sync job until it finishes."""
    def generate():
        sent_up_to = 0
        while True:
            with _sync_jobs_lock:
                job = _sync_jobs.get(job_id)
                if not job:
                    yield f"data: {json.dumps({'type': 'fatal', 'error': 'Job not found'})}\n\n"
                    return
                new_events = job['events'][sent_up_to:]
                status = job['status']
                totals = job['totals']

            for ev in new_events:
                yield f"data: {json.dumps(ev)}\n\n"
            sent_up_to += len(new_events)

            if status in ('done', 'error'):
                yield f"data: {json.dumps({'type': 'finished', 'status': status, 'totals': totals})}\n\n"
                return

            time.sleep(0.4)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/api/sync/status/<job_id>')
def api_sync_status(job_id: str):
    with _sync_jobs_lock:
        job = _sync_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found.'}), 404
    return jsonify({
        'status': job['status'],
        'events': job['events'],
        'totals': job['totals'],
        'elapsed': round(time.time() - job['started_at'], 1),
    })


@app.route('/heatmap')
def heatmap_page():
    conn = get_db_connection()
    rows = conn.execute("SELECT tags, level FROM sigma_rules WHERE tags IS NOT NULL AND tags != '[]'").fetchall()
    conn.close()

    # Build tactic → level → count grid
    from collections import defaultdict
    grid = defaultdict(lambda: defaultdict(int))
    levels = ['critical', 'high', 'medium', 'low', 'informational']

    for row in rows:
        try:
            tags = json.loads(row['tags'])
        except Exception:
            continue
        if not tags or not isinstance(tags, list):
            continue
        lvl = (row['level'] or 'informational').lower()
        if lvl not in levels:
            lvl = 'informational'
        for tag in tags:
            if not isinstance(tag, str):
                continue
            tag_lower = tag.lower()
            # match attack.tXXXX or extract tactic slug from attack.<tactic>
            for tactic_slug, _ in MITRE_TACTICS:
                if tactic_slug in tag_lower:
                    grid[tactic_slug][lvl] += 1
                    break

    # Render-friendly list: list of (slug, label, {level: count, total: n})
    heatmap_data = []
    for slug, label in MITRE_TACTICS:
        cell = dict(grid[slug])
        cell['total'] = sum(cell.values())
        heatmap_data.append({'slug': slug, 'label': label, 'counts': cell})

    return render_template('heatmap.html', heatmap_data=heatmap_data, levels=levels)


@app.route('/export')
def export_rules():
    """Export filtered rules as a YAML bundle (---‑delimited)."""
    search_query   = request.args.get('search', '').strip()
    mitre_id_query = request.args.get('mitre_id', '').strip()
    level_query    = request.args.get('level', '').strip()
    status_query   = request.args.get('status', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    # Re-use filter logic but fetch raw_rule too
    query_conditions = []
    params = []
    if search_query:
        query_conditions.append("(title LIKE ? OR description LIKE ? OR id LIKE ? OR raw_rule LIKE ?)")
        params.extend([f"%{search_query}%"] * 4)
    if mitre_id_query:
        query_conditions.append("tags LIKE ?")
        params.append(f"%{mitre_id_query}%")
    if level_query:
        query_conditions.append("level = ?")
        params.append(level_query)
    if status_query:
        query_conditions.append("status = ?")
        params.append(status_query)

    base = "SELECT raw_rule, title FROM sigma_rules"
    where = f" WHERE {' AND '.join(query_conditions)}" if query_conditions else ""
    rules = cursor.execute(base + where + " ORDER BY title ASC", tuple(params)).fetchall()
    conn.close()

    parts = [row['raw_rule'] for row in rules if row['raw_rule']]
    bundle = '\n---\n'.join(parts)

    filename = 'sigma_export.yml'
    if level_query:
        filename = f'sigma_export_{level_query}.yml'
    elif search_query:
        safe = re.sub(r'\W+', '_', search_query)[:30]
        filename = f'sigma_export_{safe}.yml'

    return Response(
        bundle,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


@app.route('/api/stats')
def api_stats():
    """Returns rule counts for new-since-last-visit badge."""
    since = request.args.get('since', '').strip()
    conn = get_db_connection()
    total = conn.execute("SELECT COUNT(*) FROM sigma_rules").fetchone()[0]
    new_since = 0
    if since:
        try:
            # since is a Unix timestamp (ms from JS)
            ts = float(since) / 1000
            dt = datetime.fromtimestamp(ts).isoformat()
            new_since = conn.execute(
                "SELECT COUNT(*) FROM sigma_rules WHERE first_seen_at > ?", (dt,)
            ).fetchone()[0]
        except (ValueError, OSError):
            pass
    conn.close()
    return jsonify({'total': total, 'new_since': new_since})


@app.route('/api/sync/history')
def api_sync_history():
    """Recent sync history, optionally filtered by source name."""
    source = request.args.get('source', '').strip()
    limit = min(int(request.args.get('limit', 20)), 100)
    try:
        _ensure_sync_history_table()
        conn = get_db_connection()
        if source:
            rows = conn.execute(
                "SELECT * FROM sync_history WHERE source_name = ? ORDER BY started_at DESC LIMIT ?",
                (source, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM sync_history ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Feature #9 — Analyst Bookmark Collections
# ---------------------------------------------------------------------------
@app.route('/collection')
def collection_page():
    """Bookmark collection viewer. Loads IDs from either ?ids=<base64> or client localStorage."""
    ids_param = request.args.get('ids', '').strip()
    shared_ids = []
    if ids_param:
        import base64
        try:
            # Add padding if missing, tolerate both url-safe and standard encodings
            s = ids_param.replace('-', '+').replace('_', '/')
            pad = (-len(s)) % 4
            decoded = base64.b64decode(s + '=' * pad).decode('utf-8')
            parsed = json.loads(decoded)
            if isinstance(parsed, list):
                shared_ids = [str(x) for x in parsed if x]
        except Exception:
            shared_ids = []

    # Fetch the shared IDs server-side so there's a non-JS fallback view
    shared_rules = []
    if shared_ids:
        conn = get_db_connection()
        placeholders = ','.join(['?'] * len(shared_ids))
        rows = conn.execute(
            f"SELECT id, title, level, status, logsource_product, description "
            f"FROM sigma_rules WHERE id IN ({placeholders})",
            shared_ids
        ).fetchall()
        conn.close()
        shared_rules = [dict(r) for r in rows]

    rule_count_conn = get_db_connection()
    rule_count = rule_count_conn.execute("SELECT COUNT(*) FROM sigma_rules").fetchone()[0]
    rule_count_conn.close()

    return render_template('collection.html',
                           shared_ids=shared_ids,
                           shared_rules=shared_rules,
                           is_shared_view=bool(shared_ids),
                           rule_count=rule_count)


@app.route('/api/bookmarks/batch', methods=['POST'])
def api_bookmarks_batch():
    payload = request.get_json(silent=True) or {}
    ids = payload.get('ids') or []
    if not isinstance(ids, list) or not ids:
        return jsonify([])

    # Limit to 500 to avoid pathological queries
    ids = [str(x) for x in ids[:500] if x]
    if not ids:
        return jsonify([])

    conn = get_db_connection()
    placeholders = ','.join(['?'] * len(ids))
    rows = conn.execute(
        f"SELECT id, title, level, status, logsource_product, description, last_updated_at "
        f"FROM sigma_rules WHERE id IN ({placeholders})",
        ids
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ---------------------------------------------------------------------------
# Feature #2 — Temporal Coverage Tide Chart
# ---------------------------------------------------------------------------
@app.route('/tide')
def tide_page():
    return render_template('tide.html')


@app.route('/api/tide-data')
def api_tide_data():
    features = _load_features()
    if not features.get('tide_chart', True):
        return jsonify({'disabled': True})

    # mode: 'ingested' uses first_seen_at, 'authored' uses rule_authored_at
    mode = request.args.get('mode', 'ingested')
    date_col = 'rule_authored_at' if mode == 'authored' else 'first_seen_at'

    conn = get_db_connection()
    rows = conn.execute(
        f"SELECT tags, {date_col} as date_val FROM sigma_rules WHERE {date_col} IS NOT NULL AND {date_col} != ''"
    ).fetchall()
    conn.close()

    from collections import defaultdict
    tactic_set = {slug for slug, _ in MITRE_TACTICS}

    # tactic -> day -> count (delta)
    per_day = defaultdict(lambda: defaultdict(int))
    all_days = set()

    for row in rows:
        raw_date = row['date_val']
        try:
            # Handles both "YYYY-MM-DD" and full ISO timestamps
            dt = datetime.fromisoformat(str(raw_date).split('.')[0].replace(' ', 'T'))
        except (ValueError, AttributeError):
            continue
        day_key = dt.strftime('%Y-%m-%d')
        all_days.add(day_key)

        tags = []
        try:
            tags = json.loads(row['tags']) if row['tags'] else []
        except (json.JSONDecodeError, TypeError):
            tags = []

        matched = set()
        for tag in tags if isinstance(tags, list) else []:
            if not isinstance(tag, str):
                continue
            low = tag.lower()
            for t in tactic_set:
                if t in low:
                    matched.add(t)
                    break

        for t in matched:
            per_day[t][day_key] += 1

    if not all_days:
        return jsonify({'days': [], 'series': [], 'mode': mode})

    days_sorted = sorted(all_days)
    series = []
    for slug, label in MITRE_TACTICS:
        if slug not in per_day:
            continue
        running = 0
        counts = []
        for d in days_sorted:
            running += per_day[slug].get(d, 0)
            counts.append(running)
        if counts[-1] > 0:
            series.append({'tactic': slug, 'label': label, 'counts': counts})

    return jsonify({'days': days_sorted, 'series': series, 'mode': mode})


# ---------------------------------------------------------------------------
# Feature #3 — Rule Decay Scoring
# ---------------------------------------------------------------------------
def _parse_date_flexible(s) -> 'datetime | None':
    """Parse an ISO-ish date string to a datetime. Handles YYYY-MM-DD and full timestamps."""
    if not s:
        return None
    try:
        clean = str(s).strip().replace('/', '-').split('.')[0]
        # YYYY-MM-DD only
        if re.match(r'^\d{4}-\d{2}-\d{2}$', clean):
            return datetime.strptime(clean, '%Y-%m-%d')
        # YYYY-MM-DD HH:MM:SS or YYYY-MM-DDTHH:MM:SS
        return datetime.fromisoformat(clean.replace('T', ' ')[:19])
    except (ValueError, AttributeError):
        return None


def _compute_decay_for_rule(row, features, now):
    """
    Compute the decay score (0–100) for a single row.

    Reference date priority (most authoritative first):
      1. rule_authored_at  — from the YAML 'modified' or 'date' field (actual author date)
      2. first_seen_at     — when the collector first saw the rule (fallback only)

    last_updated_at is intentionally NOT used: it reflects when the collector ran,
    not when the rule content was actually changed by the author.
    """
    warn_days  = int(features.get('decay_warn_days', 365))
    grey_days  = int(features.get('decay_grey_days', 550))
    hide_days  = int(features.get('decay_hide_days', 730))

    # Priority 1: author-supplied date from YAML (most accurate)
    authored = _parse_date_flexible(row['rule_authored_at'] if 'rule_authored_at' in row.keys() else None)

    # Priority 2: first_seen_at (when collector first ingested it)
    first_seen = _parse_date_flexible(row['first_seen_at'])

    ref_date = authored or first_seen
    ref_source = 'rule YAML (modified/date)' if authored else ('first_seen_at' if first_seen else None)

    if ref_date is None:
        return {
            'score': 50,
            'state': 'ok',
            'ref_date': None,
            'ref_source': None,
            'warn_date': None, 'grey_date': None, 'hide_date': None,
            'days_since_update': None,
        }

    from datetime import timedelta
    days_since = (now - ref_date).days
    warn_date = (ref_date + timedelta(days=warn_days)).strftime('%Y-%m-%d')
    grey_date = (ref_date + timedelta(days=grey_days)).strftime('%Y-%m-%d')
    hide_date = (ref_date + timedelta(days=hide_days)).strftime('%Y-%m-%d')

    score = max(0, min(100, round(100 - (days_since / hide_days) * 100))) if hide_days > 0 else 50

    if days_since < warn_days:
        state = 'ok'
    elif days_since < grey_days:
        state = 'warn'
    elif days_since < hide_days:
        state = 'grey'
    else:
        state = 'hidden'

    return {
        'score': score,
        'state': state,
        'ref_date': ref_date.strftime('%Y-%m-%d'),
        'ref_source': ref_source,
        'warn_date': warn_date,
        'grey_date': grey_date,
        'hide_date': hide_date,
        'days_since_update': days_since,
    }


@app.route('/api/decay-config', methods=['GET', 'POST'])
def api_decay_config():
    if request.method == 'GET':
        features = _load_features()
        return jsonify({
            'decay_scoring': features.get('decay_scoring', True),
            'decay_warn_days': int(features.get('decay_warn_days', 365)),
            'decay_grey_days': int(features.get('decay_grey_days', 548)),
            'decay_hide_days': int(features.get('decay_hide_days', 730)),
        })

    payload = request.get_json(silent=True) or {}
    features = _load_features()

    for key in ('decay_scoring', 'decay_warn_days', 'decay_grey_days', 'decay_hide_days'):
        if key in payload:
            if key == 'decay_scoring':
                features[key] = bool(payload[key])
            else:
                val = int(payload[key])
                if val < 1: val = 1
                features[key] = val

    try:
        dir_name = os.path.dirname(os.path.abspath('features.json')) or '.'
        fd, tmp = tempfile.mkstemp(prefix='.feat_', suffix='.tmp', dir=dir_name)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(features, f, indent=2)
        os.replace(tmp, 'features.json')
    except OSError as e:
        return jsonify({'error': str(e)}), 500

    return jsonify({'success': True, **{k: features[k] for k in features}})


@app.route('/api/decay-scores')
def api_decay_scores():
    features = _load_features()
    if not features.get('decay_scoring', True):
        return jsonify({'disabled': True, 'scores': {}})

    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, status, first_seen_at, last_updated_at, rule_authored_at FROM sigma_rules"
    ).fetchall()
    conn.close()

    now = datetime.now()
    scores = {}
    for row in rows:
        d = _compute_decay_for_rule(row, features, now)
        scores[row['id']] = d['score']

    return jsonify({'scores': scores})


@app.route('/api/decay/<rule_id>')
def api_decay_rule(rule_id):
    """Return full decay detail for a single rule."""
    features = _load_features()
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, status, first_seen_at, last_updated_at, rule_authored_at FROM sigma_rules WHERE id = ?",
        (rule_id,)
    ).fetchone()
    conn.close()
    if row is None:
        return jsonify({'error': 'Not found'}), 404
    now = datetime.now()
    d = _compute_decay_for_rule(row, features, now)
    d['config'] = {
        'decay_warn_days': int(features.get('decay_warn_days', 365)),
        'decay_grey_days': int(features.get('decay_grey_days', 548)),
        'decay_hide_days': int(features.get('decay_hide_days', 730)),
    }
    return jsonify(d)




# ---------------------------------------------------------------------------
# Feature #1 — Detection Genome Fingerprinting
# ---------------------------------------------------------------------------
def _flatten_detection_strings(obj, out):
    if obj is None:
        return
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, (int, float, bool)):
        out.append(str(obj))
    elif isinstance(obj, list):
        for item in obj:
            _flatten_detection_strings(item, out)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                out.append(k)
            _flatten_detection_strings(v, out)


def _tokenize_detection(text):
    # lowercase, strip punctuation, split on whitespace + common separators
    lowered = text.lower()
    cleaned = re.sub(r"[^\w\s\-\.]", ' ', lowered)
    tokens = re.split(r'[\s]+', cleaned)
    return {t for t in tokens if len(t) >= 3}


def _build_genome_index():
    conn = get_db_connection()
    rows = conn.execute("SELECT id, title, detection FROM sigma_rules").fetchall()
    conn.close()

    index = {}
    titles = {}
    for row in rows:
        if not row['detection']:
            continue
        try:
            det = json.loads(row['detection'])
        except (json.JSONDecodeError, TypeError):
            continue
        buf = []
        _flatten_detection_strings(det, buf)
        tokens = _tokenize_detection(' '.join(buf))
        if tokens:
            index[row['id']] = tokens
            titles[row['id']] = row['title']

    _genome_cache['index'] = index
    _genome_cache['titles'] = titles
    _genome_cache['count'] = len(rows)
    return index, titles


@app.route('/api/genome/<rule_id>')
def api_genome(rule_id):
    # Check if cache is still valid (by row count)
    conn = get_db_connection()
    current_count = conn.execute("SELECT COUNT(*) FROM sigma_rules").fetchone()[0]
    conn.close()

    if _genome_cache['index'] is None or _genome_cache['count'] != current_count:
        _build_genome_index()

    index = _genome_cache['index'] or {}
    titles = _genome_cache.get('titles', {}) or {}

    if rule_id not in index:
        return jsonify({'similar': []})

    target = index[rule_id]
    if not target:
        return jsonify({'similar': []})

    results = []
    for other_id, other_tokens in index.items():
        if other_id == rule_id or not other_tokens:
            continue
        inter = len(target & other_tokens)
        if inter == 0:
            continue
        union = len(target | other_tokens)
        if union == 0:
            continue
        jaccard = inter / union
        if jaccard > 0:
            results.append((other_id, jaccard))

    results.sort(key=lambda x: -x[1])
    top = results[:5]
    return jsonify({
        'similar': [
            {'id': rid, 'title': titles.get(rid, rid), 'score': round(score, 4)}
            for rid, score in top
        ]
    })


# ---------------------------------------------------------------------------
# Feature #8 — Rule Family Tree
# ---------------------------------------------------------------------------
@app.route('/family-tree')
def family_tree_page():
    return render_template('family_tree.html')


@app.route('/api/family-tree')
def api_family_tree():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, title, first_seen_at, level FROM sigma_rules ORDER BY first_seen_at ASC"
    ).fetchall()
    conn.close()

    from collections import defaultdict
    families = defaultdict(list)

    version_re = re.compile(r'\s+v\d+(\.\d+)*\s*$', re.IGNORECASE)
    for row in rows:
        title = row['title'] or ''
        base = version_re.sub('', title).strip().lower()
        if not base:
            continue
        families[base].append({
            'id': row['id'],
            'title': title,
            'first_seen_at': row['first_seen_at'],
            'level': row['level'] or '',
        })

    result = []
    for base_title, members in families.items():
        if len(members) < 2:
            continue
        # Use the shortest title as the display base
        display = min((m['title'] for m in members), key=lambda t: len(t))
        # strip version suffix on the display version
        display_clean = version_re.sub('', display).strip() or display
        result.append({
            'base_title': display_clean,
            'members': members,
        })

    result.sort(key=lambda f: -len(f['members']))
    return jsonify({'families': result[:50]})


# ---------------------------------------------------------------------------
# Features config endpoint
# ---------------------------------------------------------------------------
@app.route('/api/features')
def api_features():
    return jsonify(_load_features())


@app.route('/decay-config')
def decay_config_page():
    features = _load_features()
    return render_template('decay_config.html', features=features)


# ---------------------------------------------------------------------------
# Auto-Scheduler
# ---------------------------------------------------------------------------
_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()


def _get_oldest_last_sync() -> datetime | None:
    """Return the oldest last_sync timestamp across all enabled sources, or None."""
    sources = _load_config()
    enabled = [s for s in sources if s.get('enabled')]
    oldest: datetime | None = None
    for src in enabled:
        state = _load_sync_state(src['name'])
        raw = state.get('last_sync')
        if not raw:
            return None  # at least one source has never been synced → sync now
        try:
            dt = datetime.fromisoformat(raw)
        except (ValueError, TypeError):
            return None
        if oldest is None or dt < oldest:
            oldest = dt
    return oldest


def _scheduler_loop():
    """Background thread: wake every 60 s, fire a full sync when interval has elapsed."""
    while not _scheduler_stop.is_set():
        features = _load_features()
        if features.get('scheduler_enabled'):
            interval_h = float(features.get('scheduler_interval_hours', 24))
            oldest = _get_oldest_last_sync()
            now = datetime.now()
            due = (oldest is None) or ((now - oldest).total_seconds() >= interval_h * 3600)
            if due:
                sources = [s for s in _load_config() if s.get('enabled')]
                if sources:
                    job_id = _new_job(None)
                    t = threading.Thread(target=_run_sync, args=(job_id, sources), daemon=True)
                    t.start()
                    # Wait for this sync to finish before checking again
                    while not _scheduler_stop.is_set():
                        with _sync_jobs_lock:
                            job = _sync_jobs.get(job_id, {})
                        if job.get('status') in ('done', 'error'):
                            break
                        _scheduler_stop.wait(timeout=10)
                    continue  # re-evaluate immediately after sync completes
        _scheduler_stop.wait(timeout=60)


def _start_scheduler():
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _scheduler_stop.clear()
    _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True, name='scheduler')
    _scheduler_thread.start()


@app.route('/api/scheduler/status')
def api_scheduler_status():
    features = _load_features()
    enabled = features.get('scheduler_enabled', False)
    interval_h = float(features.get('scheduler_interval_hours', 24))
    oldest = _get_oldest_last_sync()
    now = datetime.now()

    next_sync_in: float | None = None
    if oldest and enabled:
        elapsed = (now - oldest).total_seconds()
        remaining = interval_h * 3600 - elapsed
        next_sync_in = max(0.0, remaining)

    return jsonify({
        'enabled': enabled,
        'interval_hours': interval_h,
        'last_sync': oldest.isoformat() if oldest else None,
        'next_sync_in_seconds': next_sync_in,
    })


@app.route('/api/scheduler/config', methods=['POST'])
def api_scheduler_config():
    payload = request.get_json(silent=True) or {}
    features = _load_features()

    if 'enabled' in payload:
        features['scheduler_enabled'] = bool(payload['enabled'])
    if 'interval_hours' in payload:
        try:
            h = float(payload['interval_hours'])
            if h < 1:
                return jsonify({'error': 'Interval must be at least 1 hour.'}), 400
            features['scheduler_interval_hours'] = h
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid interval value.'}), 400

    try:
        with open(FEATURES_FILE, 'w', encoding='utf-8') as f:
            json.dump(features, f, indent=2)
    except IOError as e:
        return jsonify({'error': str(e)}), 500

    # Restart the scheduler thread so it picks up the new config immediately
    _scheduler_stop.set()
    if _scheduler_thread:
        _scheduler_thread.join(timeout=2)
    _scheduler_stop.clear()
    _start_scheduler()

    return jsonify({'ok': True, 'features': features})


if os.path.exists(DB_FILE):
    try:
        _ensure_rule_authored_at_column()
        _ensure_sigmahq_category_columns()
    except Exception:
        pass  # Don't crash on startup if DB isn't accessible yet

_start_scheduler()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')