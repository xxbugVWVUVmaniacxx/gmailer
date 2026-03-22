---
id: WI-4
title: Add permanent delete capability
status: blocked
created: 2026-03-21
depends_on: []
triggers: []
block_reason: Pending manual request from user after evaluating Trash-based workflow
---

# WI-4 — Permanent delete

## shortdesc
Add a `permanent_delete` method and `--permanent` CLI flag that bypasses Trash and irreversibly removes messages.

## prereq
- User has validated the `safe_delete` (Trash) workflow and consciously wants a no-recovery path
- User explicitly requests this work item be executed

## steps

1. Add `permanent_delete(self, userId="me", msgId=None)` to `Gmailer`:
   ```python
   def permanent_delete(self, userId="me", msgId=None):
       return self.service.users().messages().delete(userId=userId, id=msgId).execute()
   ```

2. Add `--permanent` flag to the `__main__` argparse block. When passed alongside `--delete --confirm`, use `permanent_delete` instead of `safe_delete` in the deletion loop.

3. Update `delete_by_sender` to accept a `permanent=False` parameter and route accordingly.

4. Update `README.md` Safety notes section to document the permanent flag and its irreversibility.

5. Update `.kiro/steering/gmailer.md` method table with `permanent_delete`.

## result
`--delete EMAIL --confirm --permanent` permanently removes all messages from a sender with no recovery path. Default behavior (`--confirm` without `--permanent`) remains Trash-only.

## postreq
Update WI-4 status to `done`.
