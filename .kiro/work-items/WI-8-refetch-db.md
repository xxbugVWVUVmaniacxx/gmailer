---
id: WI-8
title: Re-run fetch_and_store to fill missing DB rows
status: blocked
priority: medium
blocked_by: [WI-7]
---

## Goal

The initial `fetch_and_store` run had ~35% error rate (26,800 of 76,819
messages not stored) due to unhandled 429s. Once WI-7 (retry backoff) is
implemented, re-run to fill the gaps.

## Approach

`INSERT OR REPLACE` semantics mean re-running is safe — existing rows are
overwritten with fresh data, missing rows are inserted. No special migration
needed.

## Steps

1. Confirm WI-7 is merged
2. Run:
   ```bash
   cd ~/code/gmailer && source .venv/bin/activate
   python3 -c "
   from src.gmailer import Gmailer
   g = Gmailer()
   ids = g.get_message_ids(cached_ok=True)
   g.fetch_and_store(ids)
   "
   ```
3. Verify row count:
   ```bash
   python3 -c "
   import sqlite3; from pathlib import Path
   conn = sqlite3.connect(Path('src/messages.db'))
   print(conn.execute('SELECT COUNT(*) FROM messages').fetchone())
   "
   ```
   Expected: ~76,800 rows (within a few hundred for messages deleted since the ID list was cached)

## Done criteria

- [ ] WI-7 merged
- [ ] `fetch_and_store` completes with <1% error rate
- [ ] `messages.db` row count ~76,800
- [ ] `--top 20` returns accurate results from DB
