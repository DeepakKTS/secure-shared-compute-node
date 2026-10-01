"""Tests for scripts/demo.py (make demo), which must change nothing.

The unit tests feed it canned command output and check what it runs and
prints, and that it writes no file. The lab test runs the real `make demo`
and checks that the repo and every lab VM are as they were before it.
"""

import ast
import io
import json
import os
import subprocess
from pathlib import Path

import demo
import lab_hosts
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / ".lab"

# What demo.py may run on the node. A change to demo.NODE_COMMANDS must be
# made here too, so a new command gets a second look: it must only read.
EXPECTED_NODE_COMMANDS = {
    "sshd": "sudo -n sshd -T",
    "nft": "sudo -n nft -j list chains",
    "fail2ban": "sudo -n fail2ban-client status sshd",
    "/tmp": "findmnt -no FSTYPE,OPTIONS --mountpoint /tmp",
    "/dev/shm": "findmnt -no FSTYPE,OPTIONS --mountpoint /dev/shm",
}

MULTIPASS = {
    "list": [
        {"name": "ssc-node", "state": "Running", "ipv4": ["192.0.2.2"]},
        {"name": "ssc-monitor", "state": "Running", "ipv4": ["192.0.2.3"]},
        {"name": "other-vm", "state": "Stopped", "ipv4": []},
    ]
}
CHAINS = {
    "nftables": [
        {"metainfo": {"version": "1.0.9"}},
        {"chain": {"family": "inet", "table": "ssc_filter", "name": "input",
                   "hook": "input", "prio": 0, "policy": "drop"}},
        {"chain": {"family": "inet", "table": "f2b-table", "name": "f2b-chain",
                   "hook": "input", "prio": -1, "policy": "accept"}},
    ]
}  # fmt: skip
FAIL2BAN = (
    "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t1\n|  |- Total failed:\t7\n"
    "`- Actions\n   |- Currently banned:\t0\n   |- Total banned:\t2\n   `- Banned IP list:\t\n"
)
NODE_OUTPUT = {
    "sudo -n sshd -T": "port 22\npermitrootlogin no\npasswordauthentication no\n"
    "kbdinteractiveauthentication no\npubkeyauthentication yes\n",
    "sudo -n nft -j list chains": json.dumps(CHAINS),
    "sudo -n fail2ban-client status sshd": FAIL2BAN,
    "findmnt -no FSTYPE,OPTIONS --mountpoint /tmp": "tmpfs  rw,nosuid,nodev,noexec,size=524288k\n",
    "findmnt -no FSTYPE,OPTIONS --mountpoint /dev/shm": "tmpfs  rw,nosuid,nodev,noexec\n",
}
NO_SUDO = "User {user} is not allowed to run sudo on ssc-node.\n"


def completed(argv, rc: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(argv, rc, out, err)


class FakeLab:
    """Stands in for demo.run: answers from canned output, records every call."""

    def __init__(self, node=None, pytest_out="227 passed, 17 deselected in 90.00s", pytest_rc=0):
        self.node = {**NODE_OUTPUT, **(node or {})}
        self.pytest = completed([], pytest_rc, f"....\n{pytest_out}\n")
        self.calls: list[tuple[list[str], dict | None]] = []

    def __call__(self, argv, env):
        self.calls.append((argv, env))
        if argv[0] == "multipass":
            return completed(argv, 0, json.dumps(MULTIPASS))
        if argv[0] == "ssh":
            command = argv[-1]
            for user in demo.research_users():
                if command == demo.SUDO_LIST.format(user=user):
                    return completed(argv, 0, self.node.get(command, NO_SUDO.format(user=user)))
            if command not in self.node:
                return completed(argv, 255, "", "ssh: connect to host ssc-node: timed out")
            return completed(argv, 0, self.node[command])
        if argv[0] == str(ROOT / ".venv" / "bin" / "pytest"):
            return self.pytest
        raise AssertionError(f"demo ran an unexpected command: {argv}")


def run_demo(lab: FakeLab) -> tuple[int, str]:
    out = io.StringIO()
    rc = demo.Demo(runner=lab, out=out).main()
    return rc, out.getvalue()


def repo_state() -> dict[str, tuple[int, int, int]]:
    """(mode, size, mtime) of every file and directory in the repo, ignored
    ones included, so a write, a new file or a removed one all show. Left
    out: .lab/audit (Claude Code's own hooks append to it), .git (an editor's
    git integration can write there; demo.py runs no git command, see
    test_demo_runs_only_multipass_ssh_and_pytest) and Finder's .DS_Store."""
    state = {}
    for top, dirs, files in os.walk(ROOT):
        here = Path(top)
        dirs[:] = [d for d in dirs if here / d not in (ROOT / ".git", LAB / "audit")]
        for name in [*dirs, *files]:
            if name == ".DS_Store":
                continue
            path = here / name
            st = path.lstat()
            state[str(path.relative_to(ROOT))] = (st.st_mode, st.st_size, st.st_mtime_ns)
    return state


def differences(before: dict, after: dict) -> list[str]:
    return sorted(
        f"{key}: {before.get(key)} -> {after.get(key)}"
        for key in set(before) | set(after)
        if before.get(key) != after.get(key)
    )


def test_summary_shows_each_item() -> None:
    rc, text = run_demo(FakeLab())
    assert rc == 0, text
    for line in (
        "  ssc-node         Running   192.0.2.2",
        "  ssc-attacker     not created",
        "  sshd -T          passwordauthentication no, permitrootlogin no,"
        " kbdinteractiveauthentication no",
        "  policy input     accept (inet f2b-table, fail2ban bans only), drop (inet ssc_filter)",
        "  policy output    no chain, so accept",
        "  fail2ban sshd    jail up; banned now 0 (total 2), failed logins now 1 (total 7)",
        "  /tmp             tmpfs rw,nosuid,nodev,noexec,size=524288k",
        "  /dev/shm         tmpfs rw,nosuid,nodev,noexec",
        "  sudo rights      alice: none, bob: none",
        "Phase 2 checks: PASS (227 passed; 17 tests that change VM state left out,"
        " `pytest -m lab` runs them)",
    ):
        assert line in text.splitlines(), (line, text)
    assert "other-vm" not in text


def test_lynis_index_comes_from_results() -> None:
    data = json.loads((ROOT / "results" / "lynis-before.json").read_text())
    _, text = run_demo(FakeLab())
    row = next(line for line in text.splitlines() if line.startswith("  before "))
    assert row.split()[1] == str(data["hardening_index"])
    assert data["git_sha"][:7] in row and "results/lynis-before.json" in row


def test_missing_lynis_result_shows_pending(monkeypatch) -> None:
    monkeypatch.setattr(demo, "LYNIS", (("after", "lynis-no-such-file.json"),))
    _, text = run_demo(FakeLab())
    assert "  after            pending (no results/lynis-no-such-file.json)" in text.splitlines()


def test_node_commands_are_the_reviewed_read_only_set() -> None:
    assert demo.NODE_COMMANDS == EXPECTED_NODE_COMMANDS
    assert demo.SUDO_LIST == "sudo -n sudo -l -U {user}"


def test_demo_runs_only_multipass_ssh_and_pytest() -> None:
    lab = FakeLab()
    run_demo(lab)
    allowed = set(EXPECTED_NODE_COMMANDS.values()) | {
        demo.SUDO_LIST.format(user=user) for user in demo.research_users()
    }
    for argv, _ in lab.calls:
        if argv[0] == "ssh":
            assert argv[-1] in allowed, argv
        else:
            assert argv in (["multipass", "list", "--format", "json"], demo.pytest_argv()), argv


def test_demo_writes_no_file() -> None:
    before = repo_state()
    run_demo(FakeLab())
    assert differences(before, repo_state()) == []


def test_ssh_writes_nothing_on_the_controller() -> None:
    # No control socket, no known_hosts update; a fresh login each time.
    argv = demo.ssh("true")
    options = {argv[i + 1] for i, arg in enumerate(argv) if arg == "-o"}
    assert {
        "ControlMaster=no",
        "ControlPath=none",
        "StrictHostKeyChecking=yes",
        "UpdateHostKeys=no",
        "BatchMode=yes",
    } <= options
    assert argv[-2:] == ["ssc-node", "true"]


def test_pytest_run_leaves_out_state_changes_and_writes_no_cache() -> None:
    argv, env = demo.pytest_argv(), demo.pytest_env()
    assert argv[argv.index("-m") + 1] == "lab and not changes_state"
    assert argv[argv.index("-p") + 1] == "no:cacheprovider"
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert env["PATH"].split(os.pathsep)[0] == str(ROOT / ".venv" / "bin")


def test_phase2_suites_are_the_harden_roles() -> None:
    # A role added to harden.yml needs its suite in the demo too.
    plays = yaml.safe_load((ROOT / "playbooks" / "harden.yml").read_text())
    roles = [role["role"] for play in plays for role in play.get("roles", [])]
    assert list(demo.PHASE2_SUITES) == [f"tests/test_{role}.py" for role in roles]
    assert all((ROOT / suite).is_file() for suite in demo.PHASE2_SUITES)


def test_tests_that_lift_bans_are_marked_changes_state() -> None:
    # attacker_unbanned runs `fail2ban-client unban`, so it changes state.
    for suite in demo.PHASE2_SUITES:
        tree = ast.parse((ROOT / suite).read_text())
        for func in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
            decorators = [ast.unparse(d) for d in func.decorator_list]
            if any("attacker_unbanned" in d for d in decorators):
                assert "pytest.mark.changes_state" in decorators, f"{suite}::{func.name}"


@pytest.mark.parametrize(
    ("summary", "rc"),
    [
        ("1 failed, 226 passed, 17 deselected in 90.00s", 1),
        ("227 passed, 1 skipped, 17 deselected in 90.00s", 0),
        ("226 passed, 1 error, 17 deselected in 90.00s", 1),
        ("244 deselected in 1.00s", 5),
        ("", 4),
    ],
)
def test_phase2_line_fails_unless_every_check_ran_and_passed(summary: str, rc: int) -> None:
    code, text = run_demo(FakeLab(pytest_out=summary, pytest_rc=rc))
    assert code == 1
    assert text.splitlines()[-1].startswith("Phase 2 checks: FAIL"), text


def test_research_user_with_sudo_rights_is_flagged() -> None:
    granted = "User alice may run the following commands on ssc-node:\n    (ALL) ALL\n"
    code, text = run_demo(FakeLab(node={"sudo -n sudo -l -U alice": granted}))
    assert code == 1
    assert "  sudo rights      alice: HAS SUDO RIGHTS, bob: none" in text.splitlines()


def test_unreachable_node_is_an_error() -> None:
    lab = FakeLab()
    lab.node = {}
    code, text = run_demo(lab)
    assert code == 1
    assert "  sshd -T          ERROR: could not read" in text.splitlines()


# ---- lab test ------------------------------------------------------------

# Read-only views of what a run could change on a VM: configuration, homes,
# temp paths, mounts, firewall and fail2ban state, and the probe units some
# tests start. The temp paths are compared by their entries, without their
# own mtime and without systemd-private-* and snap-private-tmp: those belong
# to services that come and go on their own. A read such as `timedatectl`
# starts systemd-timedated on demand, and its private temp dirs appear in
# /tmp and /var/tmp and go when it exits.
VM_STATE = (
    "sudo -n find /etc /home /root /opt /usr/local /var/spool/cron"
    " /var/cache/debconf /var/lib/ssc -xdev -printf '%p %y %m %s %T@\\n' 2>&1 | sort",
    "sudo -n find /tmp /var/tmp /dev/shm -mindepth 1 -xdev -not -path '*/tmp/systemd-private-*'"
    " -not -path '/tmp/snap-private-tmp*' -printf '%p %y %m %s %T@\\n' 2>&1 | sort",
    "findmnt -rn -o TARGET,FSTYPE,OPTIONS",
    "sudo -n nft list ruleset",
    "sudo -n fail2ban-client status sshd 2>&1",
    "systemctl list-units --all --plain --no-legend 'ssc-*'",
)


def vm_state(name: str) -> list[str]:
    lines = []
    for command in VM_STATE:
        result = subprocess.run(
            demo.ssh(command)[:-2] + [name, command],
            capture_output=True, text=True, check=False, timeout=120,
        )  # fmt: skip
        assert result.returncode != 255, (name, result.stderr)
        lines += [f"{command[:40]}: {line}" for line in result.stdout.splitlines()]
    return lines


@pytest.mark.lab
def test_make_demo_changes_nothing() -> None:
    lab_hosts.hosts("node")  # skips without inventory/lab.yml
    names = [
        name
        for group in yaml.safe_load(lab_hosts.INVENTORY.read_text())["all"]["children"].values()
        for name in (group or {}).get("hosts") or {}
    ]
    repo_before = repo_state()
    vms_before = {name: vm_state(name) for name in names}
    result = subprocess.run(
        ["make", "--no-print-directory", "demo"],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=900,
    )  # fmt: skip
    vms_after = {name: vm_state(name) for name in names}
    repo_after = repo_state()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Phase 2 checks: PASS" in result.stdout
    assert differences(repo_before, repo_after) == []
    for name in names:
        gone = sorted(set(vms_before[name]) - set(vms_after[name]))
        new = sorted(set(vms_after[name]) - set(vms_before[name]))
        assert (gone, new) == ([], []), name
