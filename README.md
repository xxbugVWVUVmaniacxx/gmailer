# gmailer

## What this is

A command-line tool for bulk Gmail inbox cleanup. It fetches all message metadata and stores it in a local SQLite database (`src/messages.db`), then lets you query top senders or delete all messages from a specific sender. Deletion moves messages to Trash — not permanent — so you have a recovery window before Gmail auto-purges.

## Prerequisites

- Python 3.13+
- A Google Cloud project with the Gmail Application Programming Interface (API) enabled
- OAuth 2.0 credentials downloaded as `src/.env/credentials.json`

## Setup

```bash
git clone <repo-url>
cd gmailer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdir -p src/.env
# Place your credentials.json at src/.env/credentials.json
```

## Auth

The first run opens a browser window for OAuth consent. After you approve, the token is cached at `src/.env/token.json` and reused on subsequent runs. If the token expires, it is refreshed automatically; if refresh fails, the browser flow runs again.

## Usage

Run from the repo root with the virtual environment (venv) active:

```bash
# Show top 20 senders by message count (fetches and stores all metadata on first run)
python3 src/gmailer.py --top 20

# Preview what would be deleted (dry run — safe, no changes made)
python3 src/gmailer.py --delete someone@example.com --dry-run

# Execute deletion (moves to Trash)
python3 src/gmailer.py --delete someone@example.com --confirm
```

Example output for `--top`:

```
  4821  newsletters@example.com
  1203  noreply@someservice.com
   874  updates@anothersite.com
```

Example output for `--dry-run`:

```
Would delete 4821 messages from newsletters@example.com
Sample IDs: ['abc123', 'def456', 'ghi789']
```

## Safety notes

- `--delete` without `--confirm` always runs as a dry run — no messages are touched.
- Deletion uses Gmail's `trash` API (Application Programming Interface) call (`safe_delete`), which moves messages to Trash. This is **not** permanent deletion.
- To permanently delete, empty Trash via the Gmail UI or a separate API call. This tool does not do that.
