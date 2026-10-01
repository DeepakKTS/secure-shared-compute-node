---
description: Run the security-reviewer subagent over staged or recent changes.
---

Use the security-reviewer subagent to review `git diff --staged` (or the last commit if nothing is staged). Apply the fixes it marks as must-fix, then rerun lint and tests.
