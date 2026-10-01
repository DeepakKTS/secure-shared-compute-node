---
description: Run the exit check for the current phase and report pass or fail per item.
argument-hint: [phase number]
---

Phase: $ARGUMENTS (if empty, use "Current phase" in TODO.md).

1. Read the phase's exit check in docs/PLAN.md.
2. Run `make lint` and the phase's exit commands. For phases 2 and later also run `make idempotency` and `make verify`.
3. Report a table: check, command, result.
4. If all pass, update "Current phase" in TODO.md to the next phase and commit. If any fail, list the fix needed and do not advance.
5. Then run the security-reviewer subagent on files changed in this phase.
