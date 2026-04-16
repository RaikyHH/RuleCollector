# RuleCollector

A personal tool for collecting, organizing, and browsing [Sigma](https://github.com/SigmaHQ/sigma) detection rules from multiple GitHub repositories.

Rules are fetched into a local SQLite database. A Flask web UI lets you search, filter, and explore them. Designed around SigmaHQ as the primary source, with support for any additional community repos.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Flask](https://img.shields.io/badge/flask-3.x-lightgrey) ![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- **Rule browser** — search by title, ID, description, or full content; filter by threat level, status, MITRE ATT&CK tactic, log source, and author
- **SigmaHQ category tree** — sidebar groups rules by the full folder hierarchy (Windows → File → File Access → …)
- **Incremental sync** — uses the GitHub Git Tree API to diff repos on each sync; only changed files are downloaded
- **Auto-Sync Scheduler** — optional background scheduler syncs all enabled sources on a configurable interval
- **Tide chart** — cumulative rule count per MITRE tactic over time, switchable between ingested date and rule-authored date
- **Heatmap** — rule count per MITRE tactic × threat level matrix
- **Collection view** — bookmark rules and view them as a bundle; export as YAML
- **Family tree** — groups related rule versions and highlights detection logic differences
- **Rule decay scoring** — flags rules that haven't been updated in a configurable number of days
- **Deduplication** — interactive script to merge exact duplicates and version rules with differing detection logic

---

## Requirements

- Python 3.10+
- A GitHub personal access token (recommended for rate limits, but optional for public repos)

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Create your config file

```bash
cp config.example.json config.json
```

Edit `config.json` to add your rule sources. For GitHub repos, add a personal access token to avoid rate limiting:

- Go to [GitHub → Settings → Personal access tokens](https://github.com/settings/tokens)
- Create a token (no special scopes needed for public repos)
- Set `"github_token": "your_token_here"` on each source entry

### 3. Run the collector

```bash
python collector.py
```

This fetches all rules from enabled sources and stores them in `sigma_rules.db`. On subsequent runs, only new or changed files are downloaded (incremental sync via Git Tree API).

### 4. Start the web UI

```bash
python app.py
```

Open [http://localhost:5000](http://localhost:5000).

---

## Configuration

`config.json` is an array of source objects. Each source has:

| Field | Description |
| --- | --- |
| `name` | Display name (used as the label in the UI) |
| `url` | GitHub Contents API URL or raw file URL |
| `type` | `github_repo_folder`, `single_file_yaml`, or `raw_text_regex` |
| `enabled` | `true` / `false` — set to `false` to skip without removing |
| `github_token` | Personal access token (optional but recommended) |

### Source types

- `github_repo_folder` — recursively fetches all `.yml`/`.yaml` files from a GitHub directory using the Git Tree API
- `single_file_yaml` — downloads a single YAML rule file
- `raw_text_regex` — downloads a page and extracts rules using a regex pattern (splits on `title:` boundaries by default)

---

## Auto-Sync Scheduler

The web UI (Sources page) includes a scheduler widget. Enable it and set an interval (in hours) to have RuleCollector sync automatically in the background while the app is running. The scheduler state is saved in `features.json`.

---

## Deduplication

To interactively merge duplicates and rename versioned rules:

```bash
python deduplicator.py
```

The script shows a preview of all planned changes and asks for confirmation before writing anything.

---

## Files

| File | Description |
| --- | --- |
| `collector.py` | Fetches rules from configured sources into SQLite |
| `app.py` | Flask web server |
| `deduplicator.py` | Interactive deduplication tool |
| `config.example.json` | Example source config (copy to `config.json`) |
| `features.json` | Feature flags and scheduler/decay settings |
| `sigma_rules.db` | SQLite database — created on first run, not in git |
| `sigma_rules_files/` | Raw YAML files per rule — not in git |
| `sync_state/` | Per-source sync state (Git Tree SHA + file hashes) — not in git |

---

## License

MIT
