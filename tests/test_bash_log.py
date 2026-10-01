"""Tests for the Bash audit log: .claude/hooks/log_bash.py and bash_log.py
(written after every Bash call), and scripts/show_bash_log.py (`make
audit-log`). The hooks run from a throwaway copy of the repo layout, so
nothing is written to this repo's .lab/. These need no VMs.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import show_bash_log

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = json.loads((ROOT / ".claude" / "settings.json").read_text())


def post_hook_command(event: str) -> str:
    (entry,) = [e for e in SETTINGS["hooks"][event] if e.get("matcher") == "Bash"]
    (hook,) = entry["hooks"]
    return hook["command"]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    hooks = tmp_path / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    for source in (ROOT / ".claude" / "hooks").glob("*.py"):
        shutil.copy(source, hooks / source.name)
    return tmp_path


def run_post(repo: Path, data: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/bin/bash", "-c", post_hook_command(data["hook_event_name"])],
        input=json.dumps(data),
        env={"PATH": os.environ["PATH"], "CLAUDE_PROJECT_DIR": str(repo)},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def entries(repo: Path) -> list[dict]:
    log = repo / ".lab" / "audit" / "bash.log"
    return [json.loads(line) for line in log.read_text().splitlines()]


def call(event: str, command: str, repo: Path, **extra: object) -> dict:
    return {
        "hook_event_name": event,
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(repo),
        **extra,
    }


def test_post_hooks_are_registered_for_bash() -> None:
    for event in ("PostToolUse", "PostToolUseFailure"):
        assert ".claude/hooks/log_bash.py" in post_hook_command(event)


def test_a_successful_call_is_logged_with_its_exit_code(repo: Path) -> None:
    response = {"stdout": "", "stderr": "", "exit_code": 0, "is_interrupt": False}
    data = call("PostToolUse", "make test", repo, tool_response=response)
    assert run_post(repo, data).returncode == 0
    (entry,) = entries(repo)
    assert entry["event"] == "ran" and entry["exit"] == 0
    assert entry["command"] == "make test" and entry["cwd"] == str(repo)
    assert entry["ts"].endswith("Z")


def test_a_failed_call_is_logged_with_the_exit_code_from_the_error(repo: Path) -> None:
    data = call("PostToolUseFailure", "make lint", repo, error="Exit code 2\nruff: 1 error")
    assert run_post(repo, data).returncode == 0
    (entry,) = entries(repo)
    assert entry["exit"] == 2 and "ruff" in entry["error"]


def test_a_failure_without_an_exit_code_is_logged_as_null(repo: Path) -> None:
    data = call("PostToolUseFailure", "sleep 999", repo, error="Command timed out")
    assert run_post(repo, data).returncode == 0
    (entry,) = entries(repo)
    assert entry["exit"] is None


def test_a_log_that_cannot_be_written_is_reported(repo: Path) -> None:
    (repo / ".lab").mkdir()
    (repo / ".lab" / "audit").write_text("a file where the log directory should be\n")
    result = run_post(repo, call("PostToolUse", "ls", repo))
    assert result.returncode == 1
    assert "could not write" in result.stderr


def write_log(path: Path) -> None:
    lines = [
        {"ts": "2026-10-01T10:00:00Z", "event": "blocked", "reason": "rm outside",
         "command": "rm -rf build/", "cwd": "/r"},
        {"ts": "2026-10-01T10:01:00Z", "event": "ran", "exit": 0, "command": "make test"},
        {"ts": "2026-09-30T09:00:00Z", "event": "blocked", "reason": "day-before-reason",
         "command": "rm -f day-before-file", "cwd": "/r"},
    ]  # fmt: skip
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\nnot json\n")


def test_audit_log_lists_only_that_days_blocked_attempts(tmp_path: Path, capsys) -> None:
    log = tmp_path / "bash.log"
    write_log(log)
    assert show_bash_log.main(["--log", str(log), "--date", "2026-10-01"]) == 0
    captured = capsys.readouterr()
    assert "BLOCKED  rm outside" in captured.out and "rm -rf build/" in captured.out
    assert "make test" not in captured.out and "day-before" not in captured.out
    assert "1 blocked attempts on 2026-10-01" in captured.out
    assert "1 unreadable lines" in captured.err


def test_audit_log_all_also_lists_what_ran(tmp_path: Path, capsys) -> None:
    log = tmp_path / "bash.log"
    write_log(log)
    show_bash_log.main(["--log", str(log), "--date", "2026-10-01", "--all"])
    out = capsys.readouterr().out
    assert "exit 0" in out and "make test" in out and "2 entries on 2026-10-01" in out


def test_audit_log_without_a_log(tmp_path: Path, capsys) -> None:
    assert show_bash_log.main(["--log", str(tmp_path / "none.log")]) == 0
    assert "no log yet" in capsys.readouterr().out


def test_make_audit_log_passes_date_and_all() -> None:
    result = subprocess.run(
        ["make", "-n", "audit-log", "DATE=2026-10-01", "ALL=1"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )  # fmt: skip
    assert "scripts/show_bash_log.py --date 2026-10-01 --all" in result.stdout
