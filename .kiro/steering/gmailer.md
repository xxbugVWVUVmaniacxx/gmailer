---
inclusion: always
---

# gmailer — operator context

## Purpose and scope

Bulk Gmail inbox cleanup tool. Fetches all message metadata and stores it in a local SQLite database, then supports dry-run or confirmed deletion by sender email. Deletion is non-destructive (Trash only).

## File layout

```
src/
  gmailer.py          # All logic: Gmailer class + CLI entrypoint
  .env/
    credentials.json  # OAuth 2.0 client secrets (not committed)
    token.json        # Cached OAuth token (auto-generated on first auth)
  message_ids.json    # Cache: all inbox message IDs (auto-generated)
  messages.db         # SQLite message store (auto-generated, not committed)
requirements.txt      # Python dependencies
```

## Key class: `Gmailer` (`src/gmailer.py`)

| Method | Purpose | Notes |
|---|---|---|
| `__init__(scopes)` | Builds Gmail API service | Triggers OAuth flow if no valid token |
| `get_message_ids(cached_ok)` | Returns all inbox message IDs | Pass `cached_ok=True` to load from `message_ids.json` |
| `fetch_and_store(message_ids, flush_every)` | Batch-fetches metadata; writes to `messages.db` | Flushes every 100 batches; replaces old `get_sender_counts` |
| `get_top_senders(ranks)` | Returns top N senders as `[(email, count)]` | SQL query on `messages.db` |
| `delete_by_sender(email, dry_run)` | Deletes all messages from a sender | `dry_run=True` by default; reads IDs from `messages.db` |
| `safe_delete(userId, msgId)` | Moves a single message to Trash | Wraps `messages.trash`; not permanent deletion |
| `_init_db()` | Opens/creates `messages.db`, ensures schema | Returns `sqlite3.Connection` |
| `_upsert_messages(conn, rows)` | Bulk INSERT OR REPLACE into messages table | Commits after each call |
| `_parse_message(response)` | Extracts all fields from API response dict | Returns dict ready for `_upsert_messages` |

## DB schema

```sql
CREATE TABLE messages (
    id            TEXT PRIMARY KEY,
    thread_id     TEXT,
    sender        TEXT,
    subject       TEXT,
    internal_date INTEGER,   -- epoch ms
    size_estimate INTEGER,
    label_ids     TEXT,       -- JSON array string
    fetched_at    INTEGER     -- epoch ms
)
```

## Auth model

- Credentials: `src/.env/credentials.json` — OAuth 2.0 client secrets from Google Cloud Console
- Token cache: `src/.env/token.json` — written after first consent; auto-refreshed on expiry
- Required OAuth scope: `https://mail.google.com/` (full mailbox access)
- First run opens a local browser flow via `InstalledAppFlow`

## Safety constraints

- **Always default `dry_run=True`** when calling `delete_by_sender`. Never pass `dry_run=False` without explicit user confirmation.
- **Never call `safe_delete` in a loop** without the user having passed `--confirm` on the CLI or equivalent explicit confirmation in code.
- Deletion is Trash only — recoverable. WI-4 (permanent delete) is blocked pending user evaluation.
- `messages.db` and `src/.env/` are gitignored — never commit them.
