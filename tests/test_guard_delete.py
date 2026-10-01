"""Tests for the PreToolUse hook .claude/hooks/guard_delete.py (docs/AUTONOMY.md).

Each case feeds a command string to the exact hook command in
.claude/settings.json and checks its exit code: 0 lets the command run, 2
blocks it. The hook only reads the text; no command here is ever run. These
need no VMs.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = json.loads((ROOT / ".claude" / "settings.json").read_text())

# The two slips, exactly as the Bash tool ran them (P2.5 and P2.7 sessions).
SLIP_1 = r"""cd /Users/deepakzedler/Downloads/secure-shared-compute-node && grep -nE "^#|^\|" docs/VERSIONS.md | head -60; rm -rf /dev/null 2>/dev/null; ssh -F .lab/ssh_config -o ControlPath=none ssc-node 'rm -rf /tmp/tmp.HehpnjiNb0'"""  # noqa: E501
SLIP_2 = r"""cd /Users/deepakzedler/Downloads/secure-shared-compute-node && ssh -F .lab/ssh_config -o ControlPath=none ssc-node 'dpkg-query -W -f="\${Package} \${Version}\n" openssl libssl3t64; echo "== dpkg term log: errors or exec failures"; sudo grep -ciE "can.t exec|permission denied|error|failed" /var/log/unattended-upgrades/unattended-upgrades-dpkg.log; sudo grep -iE "can.t exec|permission denied|error|failed" /var/log/unattended-upgrades/unattended-upgrades-dpkg.log | cut -c1-200 | head -5; echo "== u-u log tail"; sudo tail -4 /var/log/unattended-upgrades/unattended-upgrades.log | cut -c1-250; echo "== still upgradable from security?"; sudo unattended-upgrade --dry-run --debug 2>&1 | grep -E "^(Packages that will be upgraded|No packages found)"; echo "== dpkg audit (half-configured packages):"; sudo dpkg --audit; echo "(end audit)"; ls /var/run/reboot-required 2>&1; findmnt -no OPTIONS /tmp'; rm -f /dev/null.bak 2>/dev/null; true"""  # noqa: E501

BLOCKED = [
    pytest.param(SLIP_1, id="slip1-as-ran"),
    pytest.param(SLIP_2, id="slip2-as-ran"),
    # The delete part of each slip on its own.
    pytest.param("rm -rf /dev/null 2>/dev/null", id="slip1-alone"),
    pytest.param("rm -f /dev/null.bak 2>/dev/null; true", id="slip2-alone"),
    # git clean, any flags; -x would reach the ignored .lab/keys.
    "git clean -fdx",
    "git clean -n",
    "git clean -fdx .lab",
    "git -C . clean -fd",
    "bash -c 'git clean -fdx'",
    # shred and truncate.
    "shred -u secrets.txt",
    "shred -u .lab/keys/admin_ed25519",
    "truncate -s 0 README.md",
    "truncate -s 0 .lab/keys/admin_ed25519",
    # rsync with a delete option.
    "rsync -a --delete src/ ./",
    "rsync -a --delete .lab/a/ ssc-node:/tmp/x/",
    "rsync -a --remove-source-files README.md .lab/x/",
    "rsync -a --delete-after .lab/a/ docs/",
    # mv onto /dev/null.
    "mv README.md /dev/null",
    "mv -t /dev/null README.md",
    "mv --target-directory=/dev/null README.md",
    "sudo mv README.md /dev/null",
    "bash -c 'mv README.md /dev/null'",
    # Deletes written as code.
    "python3 -c \"import os; os.remove('README.md')\"",
    "python3 -c 'import shutil; shutil.rmtree(\".lab\")'",
    "python3 -c 'from pathlib import Path; Path(\"x\").unlink()'",
    "perl -e 'unlink \"README.md\"'",
    "perl -MFile::Path=rmtree -e 'rmtree(\"x\")'",
    # > redirects into .lab/keys, onto tracked files, or to unknown paths.
    "echo x > .lab/keys/admin_ed25519",
    "cat /dev/null > README.md",
    "echo x >> ansible.cfg",
    "printf 'a: 1\\n' > inventory/group_vars/all.yml",
    f"echo x > {ROOT}/Makefile",
    "echo x > $HOME/notes.txt",
    # Chained, with a target outside the allowed paths.
    "git status && rm -f README.md",
    # Outside .lab/ and build output, or .lab itself and its keys.
    "rm -rf build/",
    "rm -r .lab",
    "rm -r .lab/keys",
    "rm -f .lab/keys/admin_ed25519",
    "find .lab -delete",
    "rm -f .lab/../README.md",
    "rm -f ~/.ssh/id_ed25519",
    "unlink /etc/hosts",
    "/bin/rm -r /tmp/x",
    # Targets the hook cannot predict.
    'rm -rf "$d"',
    "rm .lab/*",
    "rm -f .lab/x \\\n /etc/passwd",
    "cd / && rm -rf .lab/lynis",
    # Delete words the hook cannot check. Remote cleanup has no loophole.
    "ssh -F .lab/ssh_config ssc-node 'sudo rm -r /root/ssc-probe.abc123'",
    "bash -c 'rm -rf .lab/lynis'",
    "sudo rm -f .lab/x.json",
    "xargs rm < list.txt",
    "find .lab -exec rm {} +",
    "find . -name '*.pyc' -delete",
    "echo done # rm -rf /",
    # A known false positive: the word alone blocks. Commit with -F <file>.
    'git commit -m "drop the rm step"',
]

ALLOWED = [
    "ls -la",
    "git status",
    "make test",
    "grep -n remove docs/PLAN.md",
    "docker run --rm hello",
    "rm -f .lab/lynis/before/ssc-node-lynis-report.dat",
    "rm -r .lab/lynis/before",
    f"rm -f {ROOT}/.lab/inventory-old.yml",
    "unlink .lab/old-ssh_config",
    "rm -rf .venv",
    "rm -rf .pytest_cache .ruff_cache",
    "rm -rf tests/__pycache__",
    "find .lab/lynis -name '*.dat' -delete",
    # Chained, with every target allowed. (AUTONOMY.md still says: do not chain.)
    "git status && rm -f .lab/lynis/old.json",
    # The new delete commands with allowed targets.
    "git clean -fd .lab/lynis",
    "shred -u .lab/lynis/old.dat",
    "truncate -s 0 .lab/audit/bash.log",
    "rsync -a --delete .lab/lynis/before/ .lab/lynis/old/",
    # mv and redirects that delete or overwrite nothing protected.
    "mv .lab/a.json .lab/b.json",
    "git mv docs/a.md docs/b.md",
    "mv .lab/a .lab/b 2>/dev/null",
    "make lint > /private/tmp/lint.log 2>&1",
    "echo hi > /dev/null",
    "echo x > .lab/audit/note.txt",
    "ls 2>&1 | head",
    "echo a >&2",
    "python3 -c 'print(1)'",
]


def hook_command() -> str:
    (entry,) = [e for e in SETTINGS["hooks"]["PreToolUse"] if e.get("matcher") == "Bash"]
    (hook,) = entry["hooks"]
    assert hook["type"] == "command"
    return hook["command"]


def run_hook(stdin: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    base = {"PATH": os.environ["PATH"], "CLAUDE_PROJECT_DIR": str(ROOT)}
    return subprocess.run(
        ["/bin/bash", "-c", hook_command()],
        input=stdin,
        env={**base, **(env or {})},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def payload(command: str) -> str:
    return json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(ROOT)})


@pytest.mark.parametrize("command", BLOCKED)
def test_blocks(command: str) -> None:
    result = run_hook(payload(command))
    assert result.returncode == 2, (command, result.stderr)
    assert result.stderr.strip(), "a block must say why"


@pytest.mark.parametrize("command", ALLOWED)
def test_allows(command: str) -> None:
    result = run_hook(payload(command))
    assert result.returncode == 0, (command, result.stderr)


def test_hook_reads_the_command_and_never_runs_it(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    assert run_hook(payload(f"touch {marker}")).returncode == 0
    assert not marker.exists()


@pytest.mark.parametrize("stdin", ["not json", "{}", '{"tool_input": {"command": 7}}'])
def test_bad_input_blocks(stdin: str) -> None:
    assert run_hook(stdin).returncode == 2


def test_a_crashing_interpreter_blocks(tmp_path: Path) -> None:
    # Fail closed: python3 exits 1 here, as on an uncaught error.
    stub = tmp_path / "python3"
    stub.write_text("#!/bin/sh\nexit 1\n")
    stub.chmod(0o755)
    result = run_hook(payload("ls"), env={"PATH": f"{tmp_path}:/usr/bin:/bin"})
    assert result.returncode == 2
    assert "hook failed (exit 1)" in result.stderr


def test_a_missing_interpreter_blocks(tmp_path: Path) -> None:
    result = run_hook(payload("ls"), env={"PATH": str(tmp_path)})
    assert result.returncode == 2


def test_a_missing_hook_script_blocks(tmp_path: Path) -> None:
    result = run_hook(payload("ls"), env={"CLAUDE_PROJECT_DIR": str(tmp_path)})
    assert result.returncode == 2


def test_hook_is_registered_for_every_bash_call() -> None:
    command = hook_command()
    assert ".claude/hooks/guard_delete.py" in command
    assert command.rstrip().endswith("exit 2"), "anything but a clean allow must block"
