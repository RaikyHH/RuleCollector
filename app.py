from flask import Flask, render_template, request, jsonify
import sqlite3
import json
from datetime import datetime # Für die Anzeige im Frontend

app = Flask(__name__)
DB_FILE = 'sigma_rules.db'

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row # Ermöglicht Zugriff auf Spalten per Namen
    return conn

@app.template_filter('fromjson')
def fromjson_filter(value):
    if value:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value # Or some error indicator
    return None

@app.template_filter('pretty_yaml')
def pretty_yaml_filter(value):
    if isinstance(value, str): # If it's the raw_rule string
        return value
    try:
        # Falls es schon ein Python-Dict ist (z.B. detection)
        return yaml.dump(value, allow_unicode=True, sort_keys=False, indent=2)
    except Exception:
        return str(value) # Fallback

@app.template_filter('format_datetime')
def format_datetime_filter(value):
    if isinstance(value, str):
        try:
            # Versuche, den String in ein datetime-Objekt zu parsen
            dt_obj = datetime.fromisoformat(value.split('.')[0]) # Ignoriere Mikrosekunden für einfacheres Parsen
            return dt_obj.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value # Falls das Format nicht stimmt, gib den Originalstring zurück
    elif isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    return value


@app.route('/')
def index():
    search_query = request.args.get('search', '').strip()
    mitre_id_query = request.args.get('mitre_id', '').strip()
    level_query = request.args.get('level', '').strip()
    status_query = request.args.get('status', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT id, title, level, status FROM sigma_rules WHERE 1=1"
    params = []

    if search_query:
        query += " AND (title LIKE ? OR description LIKE ? OR id LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])
    if mitre_id_query:
        # Sucht nach Tags, die den MITRE ID String enthalten
        query += " AND tags LIKE ?"
        params.append(f"%{mitre_id_query}%") # z.B. 'attack.t1059'
    if level_query:
        query += " AND level = ?"
        params.append(level_query)
    if status_query:
        query += " AND status = ?"
        params.append(status_query)

    query += " ORDER BY title ASC"

    rules = cursor.execute(query, tuple(params)).fetchall()

    # Für die Filter-Dropdowns
    distinct_levels = [row['level'] for row in cursor.execute("SELECT DISTINCT level FROM sigma_rules WHERE level IS NOT NULL ORDER BY level").fetchall()]
    distinct_statuses = [row['status'] for row in cursor.execute("SELECT DISTINCT status FROM sigma_rules WHERE status IS NOT NULL ORDER BY status").fetchall()]

    conn.close()

    return render_template('index.html',
                           rules=rules,
                           search_query=search_query,
                           mitre_id_query=mitre_id_query,
                           level_query=level_query,
                           status_query=status_query,
                           distinct_levels=distinct_levels,
                           distinct_statuses=distinct_statuses,
                           selected_rule_id=None)

@app.route('/rule/<rule_id>')
def get_rule_details_page(rule_id):
    # Diese Route lädt die Seite neu mit der ausgewählten Regel
    search_query = request.args.get('search', '').strip()
    mitre_id_query = request.args.get('mitre_id', '').strip()
    level_query = request.args.get('level', '').strip()
    status_query = request.args.get('status', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    # Hole alle Regeln für die linke Liste (wie in index)
    list_query = "SELECT id, title, level, status FROM sigma_rules WHERE 1=1"
    list_params = []
    if search_query:
        list_query += " AND (title LIKE ? OR description LIKE ? OR id LIKE ?)"
        list_params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])
    if mitre_id_query:
        list_query += " AND tags LIKE ?"
        list_params.append(f"%{mitre_id_query}%")
    if level_query:
        list_query += " AND level = ?"
        list_params.append(level_query)
    if status_query:
        list_query += " AND status = ?"
        list_params.append(status_query)
    list_query += " ORDER BY title ASC"
    rules_list = cursor.execute(list_query, tuple(list_params)).fetchall()

    # Hole Details der ausgewählten Regel
    selected_rule = cursor.execute("SELECT * FROM sigma_rules WHERE id = ?", (rule_id,)).fetchone()

    distinct_levels = [row['level'] for row in cursor.execute("SELECT DISTINCT level FROM sigma_rules WHERE level IS NOT NULL ORDER BY level").fetchall()]
    distinct_statuses = [row['status'] for row in cursor.execute("SELECT DISTINCT status FROM sigma_rules WHERE status IS NOT NULL ORDER BY status").fetchall()]

    conn.close()

    if not selected_rule:
        return "Rule not found", 404

    return render_template('index.html',
                           rules=rules_list,
                           selected_rule=selected_rule,
                           selected_rule_id=rule_id,
                           search_query=search_query,
                           mitre_id_query=mitre_id_query,
                           level_query=level_query,
                           status_query=status_query,
                           distinct_levels=distinct_levels,
                           distinct_statuses=distinct_statuses)


# API Endpoint für dynamisches Laden (optional, falls man JavaScript-lastiger werden will)
@app.route('/api/rule/<rule_id>')
def api_get_rule(rule_id):
    conn = get_db_connection()
    rule = conn.execute('SELECT * FROM sigma_rules WHERE id = ?', (rule_id,)).fetchone()
    conn.close()
    if rule is None:
        return jsonify({'error': 'Rule not found'}), 404

    # Konvertiere sqlite3.Row zu einem Dict für jsonify
    rule_dict = dict(rule)
    # Parse JSON strings back to objects for cleaner API output
    for key in ['references', 'detection', 'falsepositives', 'tags']:
        if rule_dict[key]:
            try:
                rule_dict[key] = json.loads(rule_dict[key])
            except json.JSONDecodeError:
                pass # Behalte als String, falls es kein valides JSON ist
    return jsonify(rule_dict)

if __name__ == '__main__':
    import yaml # Für den pretty_yaml Filter im Template
    app.run(debug=True)