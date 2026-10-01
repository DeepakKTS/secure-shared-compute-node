#!/usr/bin/env python3
"""PostToolUse and PostToolUseFailure hook for the Bash tool: append the
command, its exit code and a UTC timestamp to .lab/audit/bash.log (see
bash_log.py).

A successful call carries tool_response.exit_code. A call that exits non-zero
fires PostToolUseFailure, whose payload has only an error text; the exit code
is read from its "Exit code N" when present, else recorded as null.

It never changes the tool result. If it cannot write the log it exits 1,
which Claude Code shows as a non-blocking error, so a broken log is noticed.
"""

from __future__ import annotations

import json
import re
import sys


def exit_code(data: dict) -> int | None:
    response = data.get("tool_response")
    if isinstance(response, dict) and isinstance(response.get("exit_code"), int):
        return response["exit_code"]
    if data.get("hook_event_name") == "PostToolUse":
        return 0
    match = re.search(r"[Ee]xit code (\d+)", str(data.get("error", "")))
    return int(match.group(1)) if match else None


def main() -> int:
    try:
        import bash_log

        data = json.load(sys.stdin)
        tool_input = data.get("tool_input") or {}
        entry = {
            "event": "ran",
            "exit": exit_code(data),
            "command": tool_input.get("command"),
            "cwd": data.get("cwd"),
        }
        if data.get("hook_event_name") == "PostToolUseFailure":
            entry["error"] = str(data.get("error", ""))[:300]
        bash_log.append(entry)
    except Exception as err:
        print(f"log_bash: could not write .lab/audit/bash.log ({err!r})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
