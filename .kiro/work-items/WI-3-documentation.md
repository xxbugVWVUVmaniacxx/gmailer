---
id: WI-3
title: Update documentation for human and robot operators
status: done
created: 2026-03-21
depends_on: [WI-2]
triggers: []
---

# WI-3 — Documentation

## shortdesc
Rewrite README.md for human onboarding and add a workspace steering file for robot operator context.

## prereq
- WI-2 is complete
- Final CLI interface and method signatures are stable

## steps

1. Rewrite `README.md` with the following sections:
   - **What this is**: one paragraph, plain language
   - **Prerequisites**: Python 3.13+, a Google Cloud project with Gmail API (Application Programming Interface) enabled, OAuth 2.0 credentials downloaded as `src/.env/credentials.json`
   - **Setup**: exact commands — clone, create venv, install requirements, place credentials
   - **Auth**: explain that first run opens a browser for OAuth consent; token is cached at `src/.env/token.json`
   - **Usage**: show the three CLI commands (`--top`, `--delete --dry-run`, `--delete --confirm`) with example output
   - **Safety notes**: `safe_delete` moves to Trash, not permanent deletion; permanent deletion requires a separate Gmail UI step or API call

2. Create `.kiro/steering/gmailer.md` with `inclusion: always` frontmatter:
   - Project purpose and scope
   - File layout (what each file in `src/` is for)
   - Key class: `Gmailer` in `src/gmailer.py` — methods, their purpose, and expected call order
   - Auth model: credentials location, token cache location, required OAuth scope
   - Safety constraint: always default `dry_run=True`; never call `safe_delete` in a loop without explicit user confirmation

3. Validate the steering file frontmatter using the `validation-kiro` skill:
   ```bash
   # No validator exists yet for steering files — skip, note as skill candidate
   ```

4. Read back both files and confirm they are accurate against the final code state.

## result
README.md is accurate and sufficient for a new human to set up and run the tool from scratch. `.kiro/steering/gmailer.md` gives a robot operator enough context to work on this codebase without reading the source first.

## postreq
Mark WI-3 `done`. Project is complete.

## skill candidate
A `validate_steering.py` validator (parallel to `validate_agent.py`) that checks steering file frontmatter for required `inclusion` field and valid values. Scope: `~/.kiro/skills/validation-kiro/`.
