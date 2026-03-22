---
id: WI-5
title: SQLite migration — persistent message store with incremental flush
status: done
priority: high
blocked_by: []
---

## Goal

Replace the in-memory `sender_map` + end-of-run JSON dump pattern with a SQLite
database that is written incrementally during batch processing. This eliminates
data loss on crash, enables richer queries, and stores all available metadata
at no additional API cost.

## Schema

```sql
CREATE TABLE IF NOT EXISTS messages (
    id           TEXT PRIMARY KEY,
    thread_id    TEXT,
    sender       TEXT,
    subject      TEXT,
    internal_date INTEGER,   -- epoch ms (internalDate from API)
    size_estimate INTEGER,
    label_ids    TEXT,        -- JSON array string e.g. '["INBOX","UNREAD"]'
    fetched_at   INTEGER      -- epoch ms, time this row was written
);
```

DB file: `_BASE / "messages.db"` (add to `.gitignore`).

## Changes required

### `__get_sender_request`
Expand `metadataHeaders` from `["From"]` to `["From", "Subject"]`.

### New method: `_init_db() -> sqlite3.Connection`
Open (or create) `messages.db`, run `CREATE TABLE IF NOT EXISTS`, return
connection. Use `check_same_thread=False` (batch callbacks run in same thread,
but be explicit).

### New method: `_upsert_messages(conn, rows: list[dict])`
Execute `INSERT OR REPLACE INTO messages VALUES (...)` for each row in `rows`.
Call `conn.commit()` after.

### `get_emails_from_metadata` → rename/extend to `_parse_message(response) -> dict`
Return a dict with all fields:
```python
{
    "id": ...,
    "thread_id": ...,
    "sender": ...,       # parsed from From header
    "subject": ...,      # from Subject header, or ""
    "internal_date": ...,
    "size_estimate": ...,
    "label_ids": json.dumps(response.get("labelIds", [])),
    "fetched_at": int(time.time() * 1000),
}
```

### `get_sender_counts` — rewrite as `fetch_and_store(message_ids, flush_every=100)`
- Open DB via `_init_db()`
- Accumulate parsed rows in a local list
- In callback: call `_parse_message(response)`, append to list
- After each batch: if `len(pending) >= flush_every`, call `_upsert_messages(conn, pending)`, clear list
- After all batches: flush any remaining rows
- Remove `sender_map` / `defaultdict` entirely
- Return nothing (callers query DB)

### `get_top_senders(ranks=20)` — rewrite as DB query
```python
SELECT sender, COUNT(*) as cnt FROM messages GROUP BY sender ORDER BY cnt DESC LIMIT ?
```
Remove `sender_counts.json` cache logic entirely.

### `delete_by_sender` — read IDs from DB
```python
SELECT id FROM messages WHERE sender = ?
```
Remove `get_sender_counts` call.

### `save_as` / `get_sender_counts` (old) — remove if no other callers remain

### `__main__` block — no changes needed

## Migration note

`message_ids.json` and `sender_counts.json` are superseded. After this WI is
complete, both can be deleted and removed from `.gitignore` (replace with
`messages.db`).

The existing `sender_counts.json` (if present) does NOT need to be imported —
just re-run `--top` to repopulate from the DB after the next full fetch.

## Flush threshold

Default `flush_every=100` batches = 5,000 records. Configurable via parameter.
Flush triggers when `len(pending) >= flush_every * MAX_TPS` (i.e. after
accumulating that many parsed rows, not batch count — simpler to track).

Actually: flush after each batch if `batch_number % flush_every == 0`. Simpler
and avoids off-by-one with partial final batches.

## Done criteria

- [x] `messages.db` is created and populated on first run
- [x] Crash mid-run leaves a partial but valid DB (no data loss beyond current batch)
- [x] `--top N` queries DB, no JSON file needed
- [x] `--delete EMAIL` reads IDs from DB
- [x] `sender_counts.json` and `message_ids.json` references removed from active code
- [x] `messages.db` added to `.gitignore`
- [x] Commit: `refactor: migrate to sqlite message store`
