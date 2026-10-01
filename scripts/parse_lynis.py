"""Turn a Lynis report (lynis-report.dat) into results/lynis-<label>.json.

The JSON is evidence (docs/EVIDENCE.md): README numbers come from it, so this
script fails closed. If the report lacks a field, or a value is malformed, it
exits non-zero and writes nothing.

Report times are read as UTC: playbooks/audit.yml runs Lynis with TZ=UTC,
because Lynis prints dates with no zone.

Usage: scripts/parse_lynis.py REPORT --label before|after [--out FILE] [--git-sha SHA]
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABELS = ("before", "after")
REQUIRED = ("hardening_index", "lynis_version", "hostname", "report_datetime_start")
GIT_SHA = re.compile(r"[0-9a-f]{40}(-dirty)?")


class ReportError(Exception):
    """The report cannot be turned into trustworthy evidence."""


def parse_report(text: str) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Split a report into plain keys and list keys (written as `name[]`).

    Both map to every value seen, in order. Lynis repeats some plain keys too,
    for example uncommon_network_protocol_enabled once per protocol.
    """
    values: dict[str, list[str]] = {}
    lists: dict[str, list[str]] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not key:
            raise ReportError(f"line {number} is not key=value: {line[:60]!r}")
        if key.endswith("[]"):
            lists.setdefault(key[:-2], []).append(value)
        else:
            values.setdefault(key, []).append(value)
    return values, lists


def summarize(text: str, label: str, git_sha: str) -> dict:
    """The fields docs/EVIDENCE.md defines for results/lynis-<label>.json."""
    if label not in LABELS:
        raise ReportError(f"label must be one of {', '.join(LABELS)}, got {label!r}")
    values, lists = parse_report(text)
    missing = [key for key in REQUIRED if not values.get(key, [""])[0]]
    if missing:
        raise ReportError(f"report has no {', '.join(missing)}; was the Lynis run complete?")
    # The evidence fields must be unambiguous, so each must appear exactly once.
    repeated = [f"{key} ({len(values[key])} times)" for key in REQUIRED if len(values[key]) > 1]
    if repeated:
        raise ReportError(f"report repeats {', '.join(repeated)}; expected once each")
    field = {key: values[key][0] for key in REQUIRED}
    index = field["hardening_index"]
    # ASCII digits only: str.isdigit() also accepts other scripts and "²".
    if not re.fullmatch(r"[0-9]{1,3}", index) or not 0 <= int(index) <= 100:
        raise ReportError(f"hardening_index must be a whole number from 0 to 100, got {index!r}")
    try:
        started = datetime.strptime(field["report_datetime_start"], "%Y-%m-%d %H:%M:%S")
    except ValueError as err:
        raise ReportError(f"report_datetime_start is not a date: {err}") from err
    return {
        "label": label,
        "host": field["hostname"],
        "timestamp": started.replace(tzinfo=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lynis_version": field["lynis_version"],
        "hardening_index": int(index),
        "warnings": len(lists.get("warning", [])),
        "suggestions": len(lists.get("suggestion", [])),
        "git_sha": git_sha,
    }


def head_sha() -> str:
    """The controller's git commit, so a result names the code that made it.

    Ends in -dirty when files outside results/ (tracked, or untracked and not
    ignored) differ from the commit, because then the commit alone does not
    describe that code.
    """
    sha = git("rev-parse", "HEAD")
    changed = git("status", "--porcelain", "--", ".", ":(exclude)results")
    return f"{sha}-dirty" if changed else sha


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def write_json(path: Path, data: dict) -> None:
    """Write sorted, indented JSON through a temp file, so a rerun gives no diff."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("report", type=Path, help="lynis-report.dat fetched by audit.yml")
    parser.add_argument("--label", required=True, choices=LABELS)
    parser.add_argument("--out", type=Path, help="default: results/lynis-<label>.json")
    parser.add_argument("--git-sha", help="default: git rev-parse HEAD")
    args = parser.parse_args(argv)
    out = args.out or ROOT / "results" / f"lynis-{args.label}.json"
    try:
        if args.git_sha is not None and not GIT_SHA.fullmatch(args.git_sha):
            raise ReportError(f"--git-sha must be a 40-character commit id, got {args.git_sha!r}")
        text = args.report.read_text(encoding="utf-8")
        data = summarize(text, args.label, args.git_sha or head_sha())
    except (OSError, UnicodeDecodeError, ReportError, subprocess.CalledProcessError) as err:
        print(f"parse_lynis: {err}", file=sys.stderr)
        return 1
    write_json(out, data)
    print(f"parse_lynis: wrote {out} ({data['host']}, Lynis {data['lynis_version']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
