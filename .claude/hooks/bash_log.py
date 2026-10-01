"""Append-only log of Bash calls on this host, for the owner to review what ran
during unattended work (docs/AUTONOMY.md). One JSON object per line in
.lab/audit/bash.log (gitignored, like all of .lab/):

- {"ts", "event": "ran", "exit", "command", "cwd"} from log_bash.py, after
  each Bash call (PostToolUse and PostToolUseFailure);
- {"ts", "event": "blocked", "reason", "command", "cwd"} from guard_delete.py,
  for each call it blocked (blocked calls fire no Post event).

Timestamps are UTC. Written for Python 3.9 and later, like the hooks.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

# The repo this file is in; the log never goes anywhere else.
ROOT = Path(os.path.realpath(Path(__file__).parent.parent.parent))
LOG = ROOT / ".lab" / "audit" / "bash.log"


def now_utc() -> str:
    # timezone.utc, not datetime.UTC: the hooks also run on Python 3.9 and 3.10.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: UP017


def append(entry: dict) -> None:
    LOG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    line = json.dumps({"ts": now_utc(), **entry}, ensure_ascii=False)
    with LOG.open("a", encoding="utf-8") as log:
        log.write(line + "\n")
