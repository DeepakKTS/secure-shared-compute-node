---
description: Pick and complete the next unchecked TODO task, with plan, implementation, and verification.
---

1. Read CLAUDE.md (rules), TODO.md (current phase), and the matching feature rows in docs/FEATURES.md.
2. Pick the first unchecked task in the current phase. Say which task and which feature IDs it covers.
3. Load the relevant skill from .claude/skills/.
4. Write a short plan: files to create or change, and the exact commands you will run to verify.
5. Implement.
6. Run the verification. If it fails, fix and rerun. Do not check the box on a failure.
7. Check the box in TODO.md, commit with a conventional message, and put the verification command and its key output in the commit body.
8. Stop and report: what changed, what was verified, anything in the docs you corrected, and the next task.
