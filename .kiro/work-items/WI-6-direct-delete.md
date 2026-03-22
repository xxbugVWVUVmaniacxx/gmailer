---
id: WI-6
title: Direct delete by sender via API query
status: done
priority: high
blocked_by: []
---

## Goal

Add a `--delete-direct` CLI flag that deletes all messages from a sender by
querying the Gmail API live (`messages.list` with `q="from:EMAIL"`), bypassing
the local SQLite database entirely. Useful when the DB is not yet populated.

## Changes required

### New method: `delete_by_sender_direct(email, dry_run=True)`

```python
def delete_by_sender_direct(self, email: str, dry_run: bool = True):
    ids = []
    req = self.service.users().messages().list(
        userId=self.userId, q=f"from:{email}", maxResults=500
    )
    while req is not None:
        res = req.execute()
        ids.extend(m["id"] for m in res.get("messages", []))
        req = self.service.users().messages().list_next(req, res)
    if not ids:
        print(f"No messages found for {email}")
        return
    if dry_run:
        print(f"Would delete {len(ids)} messages from {email}")
        print(f"Sample IDs: {ids[:3]}")
        return
    for i, id in enumerate(ids, 1):
        self.safe_delete(msgId=id)
        if i % 50 == 0:
            print(f"Deleted {i}/{len(ids)}...")
    print(f"Done. Deleted {len(ids)} messages from {email}.")
```

### `__main__` block

Add `--delete-direct` argument (same shape as `--delete`):

```python
parser.add_argument("--delete-direct", metavar="EMAIL", help="Delete all messages from EMAIL via live API query (no DB required)")
```

Add handling:

```python
if args.delete_direct:
    dry = not args.confirm or args.dry_run
    g.delete_by_sender_direct(args.delete_direct, dry_run=dry)
```

## Done criteria

- [x] `--delete-direct EMAIL --dry-run` prints count and sample IDs
- [x] `--delete-direct EMAIL --confirm` trashes all matching messages
- [x] `--help` shows the new flag
- [x] Work item committed alongside code change with status `done`
- [x] Commit: `feat: add direct delete by sender via api query`
