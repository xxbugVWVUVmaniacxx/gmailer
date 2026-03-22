---
id: WI-2
title: Implement deletion workflow and CLI entrypoint
status: done
created: 2026-03-21
depends_on: [WI-1]
triggers: WI-3
---

# WI-2 — Complete deletion workflow

## shortdesc
Add `delete_by_sender()` with a dry-run confirmation gate and a CLI entrypoint so the tool is runnable without a Python REPL.

## prereq
- WI-1 is complete and smoke test passed
- `sender_counts.json` exists (or will be generated on first run)

## steps

1. Add `delete_by_sender(self, email: str, dry_run: bool = True)` to the `Gmailer` class:
   - Call `get_sender_counts()` to get the full `sender_map` (use cached `message_ids.json` if present).
   - Look up `sender_map[email]` to get the list of message IDs for that sender.
   - If `dry_run=True`: print the count and a sample of 3 IDs, then return without deleting.
   - If `dry_run=False`: iterate the IDs and call `self.safe_delete(msgId=id)` for each, printing progress every 50 deletions.

2. Add a `__main__` block at the bottom of `gmailer.py` with a minimal CLI using `argparse`:
   - `--top N` — print top N senders (default 20)
   - `--delete EMAIL` — delete all messages from EMAIL (requires `--confirm` flag)
   - `--confirm` — required alongside `--delete` to prevent accidental deletion
   - `--dry-run` — show what would be deleted without deleting (default behavior for `--delete` without `--confirm`)

3. Sanity test dry-run:
   ```bash
   cd src
   python3 gmailer.py --top 5
   ```
   Expected: prints top 5 senders with counts.

4. Sanity test delete dry-run (use a real sender from the top list output):
   ```bash
   python3 gmailer.py --delete "sender@example.com" --dry-run
   ```
   Expected: prints message count and 3 sample IDs, no deletion occurs.

## result
`delete_by_sender()` exists with a working dry-run gate. CLI entrypoint works for both listing and deletion workflows. No messages are deleted without explicit `--confirm`.

## postreq
Update `WI-2` status to `done` and proceed to `WI-3`.
