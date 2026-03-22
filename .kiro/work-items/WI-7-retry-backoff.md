---
id: WI-7
title: Retry logic for fetch_and_store on 429/500 errors
status: ready
priority: high
blocked_by: []
---

## Goal

`fetch_and_store` currently silently drops batch responses that fail with
429 (rate limit) or 500 (server error). ~35% of the first full run was lost
this way. Add exponential backoff retry so failed batches are retried before
being skipped.

## Changes required

### `fetch_and_store` — wrap `batch.execute()` with retry

Replace the bare `batch.execute()` call with a retry loop:

```python
import random

def _execute_with_retry(batch, max_retries=5, base_delay=5):
    for attempt in range(max_retries):
        try:
            batch.execute()
            return
        except HttpError as e:
            if e.resp.status in (429, 500, 503) and attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                print(f"batch error {e.resp.status}, retrying in {delay:.1f}s...")
                time.sleep(delay)
            else:
                raise
```

Call `_execute_with_retry(batch)` instead of `batch.execute()` in
`fetch_and_store`.

### Sleep adjustment

Keep the existing 5s sleep between batches. The retry adds additional delay
only on failure — no change to the happy path.

## Done criteria

- [ ] Failed batches with 429/500/503 are retried up to 5 times with exponential backoff
- [ ] Successful batches are unaffected (no added latency)
- [ ] Retry attempts print a message with status code and delay
- [ ] Work item committed alongside code change with status `done`
- [ ] Commit: `fix: add retry backoff to fetch_and_store batch execution`
