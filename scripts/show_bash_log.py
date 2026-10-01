"""Show entries from .lab/audit/bash.log, the log the hooks in .claude/hooks/
write for every Bash call on this host. `make audit-log` runs it: by default,
the calls the guard hook blocked today (UTC)."""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG = ROOT / ".lab" / "audit" / "bash.log"


def indent(text: str) -> str:
    return "\n".join("    " + line for line in text.splitlines() or [""])


def describe(entry: dict) -> str:
    command = entry.get("command")
    body = indent(command if isinstance(command, str) else "(command not readable)")
    if entry.get("event") == "blocked":
        return f"{entry.get('ts')}  BLOCKED  {entry.get('reason')}\n{body}"
    return f"{entry.get('ts')}  exit {entry.get('exit')}\n{body}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--date", default=datetime.now(UTC).strftime("%Y-%m-%d"),
                        help="UTC day, YYYY-MM-DD (default: today)")  # fmt: skip
    parser.add_argument("--all", action="store_true", help="also list the commands that ran")
    args = parser.parse_args(argv)
    if not args.log.exists():
        print(f"no log yet at {args.log}")
        return 0
    shown = unreadable = 0
    for line in args.log.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            unreadable += 1
            continue
        if not str(entry.get("ts", "")).startswith(args.date):
            continue
        if entry.get("event") != "blocked" and not args.all:
            continue
        shown += 1
        print(describe(entry))
    what = "entries" if args.all else "blocked attempts"
    print(f"{shown} {what} on {args.date} (UTC) in {args.log}")
    if unreadable:
        print(f"warning: {unreadable} unreadable lines in {args.log}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
