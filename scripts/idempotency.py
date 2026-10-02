"""Run the hardening playbook twice and fail if the second run changes
anything (make idempotency, F-28, CLAUDE.md rule 5).

The first run brings the lab to the declared state. The second must then
find nothing to do: changed=0, failed=0 and unreachable=0 for every host in
its PLAY RECAP. A task that reports a change on every run hides real drift,
because a real change would look the same. A second run that names no host
fails too, so an empty inventory cannot pass.

Both runs print their output as they go. When the second run changes
something, the tasks that changed are listed at the end.

Usage: scripts/idempotency.py [ansible-playbook options, such as --tags base]
Exit 0 when both runs succeed and the second changes nothing.
"""

import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAYBOOK = "playbooks/harden.yml"
ANSIBLE_PLAYBOOK = ".venv/bin/ansible-playbook"

ANSI = re.compile(r"\x1b\[[0-9;]*m")
RECAP = re.compile(
    r"^(?P<host>\S+)\s+:\s+ok=(?P<ok>\d+)\s+changed=(?P<changed>\d+)\s+"
    r"unreachable=(?P<unreachable>\d+)\s+failed=(?P<failed>\d+)\b"
)
TASK = re.compile(r"^(?:TASK|RUNNING HANDLER) \[(?P<name>.*)\]")
CHANGED = re.compile(r"^changed: \[(?P<host>[^\]]+)\]")

# Runs a command from the repo root; returns its exit code and output lines.
Runner = Callable[[list[str]], tuple[int, list[str]]]


@dataclass(frozen=True)
class HostRecap:
    host: str
    ok: int
    changed: int
    unreachable: int
    failed: int

    @property
    def clean(self) -> bool:
        return self.changed == 0 and self.unreachable == 0 and self.failed == 0


def stream(argv: list[str]) -> tuple[int, list[str]]:
    """Run a command, print its output as it comes, and keep the lines."""
    lines = []
    with subprocess.Popen(
        argv,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    ) as proc:
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            lines.append(line.rstrip("\n"))
    return proc.returncode, lines


def plain(lines: Iterable[str]) -> list[str]:
    """The lines without color codes, in case color was forced on."""
    return [ANSI.sub("", line) for line in lines]


def recap(lines: Iterable[str]) -> list[HostRecap]:
    """Host counts from the last PLAY RECAP in a run's output."""
    found: list[HostRecap] = []
    in_recap = False
    for line in plain(lines):
        if line.startswith("PLAY RECAP"):
            in_recap, found = True, []
            continue
        match = RECAP.match(line) if in_recap else None
        if match:
            counts = (int(match[key]) for key in ("ok", "changed", "unreachable", "failed"))
            found.append(HostRecap(match["host"], *counts))
    return found


def changed_tasks(lines: Iterable[str]) -> list[tuple[str, str]]:
    """(host, task) for every task or handler that reported a change."""
    task = ""
    found = []
    for line in plain(lines):
        if match := TASK.match(line):
            task = match["name"]
        elif match := CHANGED.match(line):
            found.append((match["host"], task))
    return found


def check(extra: list[str], runner: Runner = stream, out=sys.stdout) -> int:
    argv = [ANSIBLE_PLAYBOOK, PLAYBOOK, *extra]
    lines: list[str] = []
    for run in ("first", "second"):
        print(f"== idempotency: {run} run: {' '.join(argv)}", file=out, flush=True)
        code, lines = runner(argv)
        if code != 0:
            print(f"idempotency: FAIL, the {run} run exited {code}", file=out)
            return 1
    hosts = recap(lines)
    if not hosts:
        print("idempotency: FAIL, the second run has no PLAY RECAP with a host", file=out)
        return 1
    print("== idempotency: second run", file=out)
    for host in hosts:
        print(
            f"  {host.host:<14} changed={host.changed} unreachable={host.unreachable}"
            f" failed={host.failed}",
            file=out,
        )
    if all(host.clean for host in hosts):
        print("idempotency: PASS, the second run changed nothing", file=out)
        return 0
    for host, task in changed_tasks(lines):
        print(f"  changed on the second run: {host}: {task}", file=out)
    print("idempotency: FAIL, the second run changed something or did not finish", file=out)
    return 1


if __name__ == "__main__":
    sys.exit(check(sys.argv[1:]))
