"""Print a short summary of the live lab, and change nothing on it (make demo).

It reads results/ and asks the VMs. Every command it runs on ssc-node is in
NODE_COMMANDS, each of which only reads. The SSH logins and sudo calls still
add lines to the VMs' journals; that is the only trace it leaves there.

The last line runs the Phase 2 testinfra suites without the tests marked
`changes_state` (a test ban, a temp file, a probe unit, a log file), so it
changes nothing either. `pytest -m lab` runs them all. That run takes
minutes, so its result is saved to .lab/demo/phase2.json, the one file the
demo writes. With --quick (make demo QUICK=1) the suites are not run, and the
saved result is shown with the time it was saved.

tests/test_demo.py checks all of this, and that a real run leaves the repo
(apart from that file) and the VMs as they were.

Usage: scripts/demo.py [--quick] (exit 0 when every check worked and passed)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / ".lab"
# A full run saves its Phase 2 result here, and --quick shows it.
SAVED = LAB / "demo" / "phase2.json"
RERUN = "run `make demo` once without QUICK=1"
NODE = "ssc-node"
LAB_VMS = ("ssc-node", "ssc-monitor", "ssc-attacker")
NODE_VARS = ROOT / "inventory" / "group_vars" / "node.yml"

# (label, file in results/, note). Numbers come only from these files.
LYNIS = (
    ("before", "lynis-before.json", ""),
    (
        "interim-p2",
        "lynis-interim-p2.json",
        "interim: not comparable to the final after-audit until P7.0a to P7.0c are done",
    ),
)

PHASE2_SUITES = (
    "tests/test_base.py",
    "tests/test_users.py",
    "tests/test_ssh_hardening.py",
    "tests/test_firewall.py",
    "tests/test_fail2ban.py",
    "tests/test_auto_updates.py",
    "tests/test_tmp_hardening.py",
    "tests/test_auditd.py",
)
READ_ONLY_TESTS = "lab and not changes_state"

SSHD_KEYS = ("passwordauthentication", "permitrootlogin", "kbdinteractiveauthentication")
HOOKS = ("input", "forward", "output")

# Every command the demo runs on the node. Each one only reads.
NODE_COMMANDS = {
    "sshd": "sudo -n sshd -T",
    "nft": "sudo -n nft -j list chains",
    "fail2ban": "sudo -n fail2ban-client status sshd",
    "/tmp": "findmnt -no FSTYPE,OPTIONS --mountpoint /tmp",
    "/dev/shm": "findmnt -no FSTYPE,OPTIONS --mountpoint /dev/shm",
}
SUDO_LIST = "sudo -n sudo -l -U {user}"

Runner = Callable[[list[str], dict[str, str] | None], subprocess.CompletedProcess[str]]


def run(argv: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, check=False)


def ssh(command: str) -> list[str]:
    """A fresh SSH login to the node that writes nothing on the controller:
    no control socket, and no known_hosts update (an unknown key fails)."""
    return [
        "ssh", "-F", str(LAB / "ssh_config"),
        "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "ControlMaster=no", "-o", "ControlPath=none",
        "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
        NODE, command,
    ]  # fmt: skip


def pytest_argv() -> list[str]:
    # No cache directory; PYTHONDONTWRITEBYTECODE (pytest_env) stops __pycache__.
    return [
        str(ROOT / ".venv" / "bin" / "pytest"),
        "-m", READ_ONLY_TESTS, "-p", "no:cacheprovider", "-q", "--no-header",
        *PHASE2_SUITES,
    ]  # fmt: skip


def pytest_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = f"{ROOT / '.venv' / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def research_users() -> list[str]:
    return [user["name"] for user in yaml.safe_load(NODE_VARS.read_text())["users_research"]]


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_saved(path: Path) -> tuple[dict | None, str]:
    """The saved Phase 2 result, or why it cannot be shown."""
    try:
        record = json.loads(path.read_text())
    except FileNotFoundError:
        return None, f"no saved result; {RERUN}"
    except (OSError, ValueError):
        return None, f"saved result unreadable; {RERUN}"
    if not isinstance(record, dict):
        return None, f"saved result unreadable; {RERUN}"
    counts = record.get("counts")
    if not (
        re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", str(record.get("saved_at")))
        and isinstance(record.get("passed"), bool)
        and isinstance(counts, dict)
        and all(isinstance(n, int) for n in counts.values())
    ):
        return None, f"saved result unreadable; {RERUN}"
    # A suite added since the save would be missing from the result.
    if record.get("suites") != list(PHASE2_SUITES) or record.get("marker") != READ_ONLY_TESTS:
        return None, f"saved result is for other suites; {RERUN}"
    return record, ""


class Demo:
    def __init__(
        self,
        runner: Runner = run,
        out=sys.stdout,
        quick: bool = False,
        saved: Path | None = None,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self.runner = runner
        self.out = out
        self.quick = quick
        self.saved = saved or SAVED
        self.clock = clock
        self.ok = True

    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def row(self, name: str, value: str) -> None:
        self.say(f"  {name:<16} {value}")

    def problem(self, name: str, text: str) -> None:
        self.ok = False
        self.row(name, f"ERROR: {text}")

    def node(self, command: str) -> str | None:
        result = self.runner(ssh(command), None)
        if result.returncode != 0:
            return None
        return result.stdout

    def vms(self) -> None:
        self.say("Lab VMs (multipass list)")
        try:
            result = self.runner(["multipass", "list", "--format", "json"], None)
        except FileNotFoundError:
            self.problem("multipass", "not installed")
            return
        if result.returncode != 0:
            self.problem("multipass", (result.stderr.strip() or "list failed").splitlines()[0])
            return
        listed = {vm["name"]: vm for vm in json.loads(result.stdout)["list"]}
        for name in LAB_VMS:
            vm = listed.get(name)
            if vm is None:
                self.row(name, "not created")
                continue
            self.row(name, f"{vm['state']:<9} {', '.join(vm['ipv4'])}")

    def lynis(self) -> None:
        self.say(f"Lynis hardening index on {NODE} (from results/)")
        for label, name, note in LYNIS:
            path = ROOT / "results" / name
            if not path.exists():
                self.row(label, f"pending (no results/{name})")
            else:
                data = json.loads(path.read_text())
                self.row(
                    label,
                    f"{data['hardening_index']:<4} {data['timestamp']},"
                    f" Lynis {data['lynis_version']}, git {data['git_sha'][:7]} (results/{name})",
                )
            if note:
                self.row("", note)

    def sshd(self) -> None:
        dump = self.node(NODE_COMMANDS["sshd"])
        if dump is None:
            self.problem("sshd -T", "could not read")
            return
        values = dict(line.partition(" ")[::2] for line in dump.splitlines())
        self.row("sshd -T", ", ".join(f"{key} {values.get(key, '?')}" for key in SSHD_KEYS))

    def firewall(self) -> None:
        listing = self.node(NODE_COMMANDS["nft"])
        if listing is None:
            self.problem("nftables", "could not list chains")
            return
        chains = [item["chain"] for item in json.loads(listing)["nftables"] if "chain" in item]
        for hook in HOOKS:
            # In priority order: the order the kernel runs them in.
            found = sorted((c for c in chains if c.get("hook") == hook), key=lambda c: c["prio"])
            if not found:
                self.row(f"policy {hook}", "no chain, so accept")
                continue
            self.row(
                f"policy {hook}",
                ", ".join(
                    f"{c['policy']} ({c['family']} {c['table']}"
                    + (", fail2ban bans only)" if c["table"] == "f2b-table" else ")")
                    for c in found
                ),
            )

    def fail2ban(self) -> None:
        status = self.node(NODE_COMMANDS["fail2ban"])
        if status is None:
            self.problem("fail2ban sshd", "jail not running")
            return
        count = {
            key: re.search(rf"{key}:\s+(\d+)", status)
            for key in ("Currently banned", "Total banned", "Currently failed", "Total failed")
        }
        if not all(count.values()):
            self.problem("fail2ban sshd", "unexpected status output")
            return
        n = {key: match.group(1) for key, match in count.items()}
        self.row(
            "fail2ban sshd",
            f"jail up; banned now {n['Currently banned']} (total {n['Total banned']}),"
            f" failed logins now {n['Currently failed']} (total {n['Total failed']})",
        )

    def mounts(self) -> None:
        for path in ("/tmp", "/dev/shm"):
            line = self.node(NODE_COMMANDS[path])
            if not line:
                self.problem(path, "not a mount point")
                continue
            self.row(path, " ".join(line.split()))

    def sudo_rights(self) -> None:
        rights = []
        for user in research_users():
            listing = self.node(SUDO_LIST.format(user=user))
            if listing is None:
                self.problem("sudo rights", f"could not list {user}")
                return
            if "is not allowed to run sudo" in listing:
                rights.append(f"{user}: none")
            else:
                self.ok = False
                rights.append(f"{user}: HAS SUDO RIGHTS")
        self.row("sudo rights", ", ".join(rights))

    def phase2(self) -> None:
        result = self.runner(pytest_argv(), pytest_env())
        tail = result.stdout.strip().splitlines()[-1:] or [""]
        counts = summary_counts(tail[0])
        passed = (
            result.returncode == 0
            and counts.get("passed", 0) > 0
            and not any(counts.get(key) for key in ("failed", "error", "errors", "skipped"))
        )
        self.show_phase2(passed, counts)
        self.save_phase2(
            {
                "saved_at": self.clock(),
                "passed": passed,
                "counts": counts,
                "returncode": result.returncode,
                "suites": list(PHASE2_SUITES),
                "marker": READ_ONLY_TESTS,
            }
        )

    def save_phase2(self, record: dict) -> None:
        # Written whole and then renamed, so --quick never reads half a file.
        partial = self.saved.with_name(self.saved.name + ".partial")
        try:
            self.saved.parent.mkdir(parents=True, exist_ok=True)
            partial.write_text(json.dumps(record, indent=2) + "\n")
            os.replace(partial, self.saved)
        except OSError as err:
            self.ok = False
            self.say(f"  could not save it for QUICK=1: {err}")
            return
        self.say(f"  saved for QUICK=1 in {os.path.relpath(self.saved, ROOT)}")

    def phase2_saved(self) -> None:
        record, error = read_saved(self.saved)
        if record is None:
            self.ok = False
            self.say(f"Phase 2 checks: {error}")
            return
        self.show_phase2(record["passed"], record["counts"])
        self.say(
            f"  saved {record['saved_at']} by the last full `make demo`; QUICK=1 did not rerun them"
        )

    def show_phase2(self, passed: bool, counts: dict[str, int]) -> None:
        self.ok = self.ok and passed
        left_out = counts.get("deselected", 0)
        detail = ", ".join(f"{n} {key}" for key, n in counts.items() if key != "deselected")
        self.say(
            f"Phase 2 checks: {'PASS' if passed else 'FAIL'} ({detail or 'no summary'};"
            f" {left_out} tests that change VM state left out, `pytest -m lab` runs them)"
        )

    def main(self) -> int:
        self.say("Secure Shared Compute Node: live lab summary (changes nothing on the VMs)")
        self.say(f"Live values read {self.clock()}")
        self.say()
        self.vms()
        self.say()
        self.lynis()
        self.say()
        self.say(f"{NODE} now")
        self.sshd()
        self.firewall()
        self.fail2ban()
        self.mounts()
        self.sudo_rights()
        self.say()
        if self.quick:
            self.phase2_saved()
        else:
            self.phase2()
        return 0 if self.ok else 1


def summary_counts(line: str) -> dict[str, int]:
    """Counts from pytest's last line, such as "120 passed, 9 deselected in 80.1s"."""
    return {
        key: int(n)
        for n, key in re.findall(
            r"(\d+) (passed|failed|errors?|skipped|deselected|xfailed|xpassed)", line
        )
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only summary of the live lab.")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="show the saved Phase 2 result instead of running the suites",
    )
    args = parser.parse_args(argv)
    return Demo(quick=args.quick).main()


if __name__ == "__main__":
    sys.exit(main())
