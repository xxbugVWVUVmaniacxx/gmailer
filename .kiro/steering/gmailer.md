---
inclusion: always
---

# gmailer — operator context

## Purpose and scope

Bulk Gmail inbox cleanup tool. Fetches all message IDs, groups by sender, and supports dry-run or confirmed deletion by sender email. Deletion is non-destructive (Trash only). No permanent deletion capability exists in this codebase.

## File layout

```
src/
  gmailer.py          # All logic: Gmailer class + CLI entrypoint
  .env/
    credentials.json  # OAuth 2.0 client secrets (not committed)
    token.json        # Cached OAuth token (auto-generated on first auth)
  message_ids.json    # Cache: all inbox message IDs (auto-generated)
  sender_counts.json  # Cache: {email: count} map (auto-generated)
requirements.txt      # Python dependencies
```

## Key class: `Gmailer` (`src/gmailer.py`)

| Method | Purpose | Notes |
|---|---|---|
| `__init__(scopes)` | Builds Gmail API service | Triggers OAuth flow if no valid token |
| `get_message_ids(cached_ok)` | Returns all inbox message IDs | Pass `cached_ok=True` to load from `message_ids.json` |
| `get_sender_counts(message_ids)` | Batch-fetches From headers; returns `{email: [id, ...]}` | Uses Gmail batch API (Application Programming Interface), 50 req/batch with 5s sleep |
| `get_top_senders(ranks)` | Returns top N senders as `[(email, count)]` | Loads from `sender_counts.json` cache if present |
| `delete_by_sender(email, dry_run)` | Deletes all messages from a sender | `dry_run=True` by default — only prints, no API calls |
| `safe_delete(userId, msgId)` | Moves a single message to Trash | Wraps `messages.trash`; not permanent deletion |
| `get_emails_from_metadata(message_metadata)` | Extracts sender email from message metadata dict | Returns `(email, id)` tuple |

Expected call order for deletion workflow:
1. `get_message_ids()` → full ID list
2. `get_sender_counts(ids)` → sender map
3. `delete_by_sender(email, dry_run=False)` → executes deletion

## Auth model

- Credentials: `src/.env/credentials.json` — OAuth 2.0 client secrets from Google Cloud Console
- Token cache: `src/.env/token.json` — written after first consent; auto-refreshed on expiry
- Required OAuth scope: `https://mail.google.com/` (full mailbox access)
- First run opens a local browser flow via `InstalledAppFlow`

## Safety constraints

- **Always default `dry_run=True`** when calling `delete_by_sender`. Never pass `dry_run=False` without explicit user confirmation.
- **Never call `safe_delete` in a loop** without the user having passed `--confirm` on the CLI or equivalent explicit confirmation in code.
- Deletion is Trash only — recoverable. There is no permanent delete path in this codebase.
