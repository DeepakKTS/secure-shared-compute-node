"""Print a short summary of the live lab, and change nothing on it (make demo).

It reads results/ and asks the VMs. Every command it runs on ssc-node is in
NODE_COMMANDS, each of which only reads. The SSH logins and sudo calls still
add lines to the VMs' journals; that is the only trace it leaves there.

The last line runs the Phase 2 testinfra suites without the tests marked
`changes_state` (a test ban, a temp file, a probe unit, a log file), so it
changes nothing either. `pytest -m lab` runs them all. That run takes
minutes, so its result is saved to .lab/demo/phase2.json. With --quick (make
demo QUICK=1) the suites are not run, and the saved result is shown with the
time it was saved.

With --html (make demo-html) it shows the same data as --quick, and also
writes it as a page to .lab/demo/index.html: one file, no scripts, and
nothing loaded from elsewhere, so it works offline. The page looks like a
terminal: each section shows the command that produced its values, as a
prompt line, then the values, and the command's raw output opens on a
click. Above them, a drawing of the lab shows each machine's state and the
flows that exist now, and a strip shows the build stages from TODO.md.
--open then opens the page with macOS `open`. With --live (make demo-live)
it rebuilds the page every 30 s until Ctrl+C, and only that page reloads
itself. Those two files in .lab/demo/ are the only ones the demo writes;
--quick alone writes none.

A run that writes into .lab/demo/ (a full run, or --html) holds an
exclusive lock on that directory for the whole run, so two runs never write
it at once. One that finds the lock taken stops at once and writes nothing.
--quick alone only reads, so it takes no lock.

tests/test_demo.py checks all of this, and that a real run leaves the repo
(apart from those files) and the VMs as they were.

Usage: scripts/demo.py [--quick | --html [--open] [--live]]
Exit 0 when every check worked and passed.
"""

import argparse
import fcntl
import html
import io
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / ".lab"
# A full run saves its Phase 2 result here, and --quick shows it.
SAVED = LAB / "demo" / "phase2.json"
# --html writes the summary here.
PAGE = LAB / "demo" / "index.html"
RERUN = "run `make demo` once without QUICK=1"
NODE = "ssc-node"
# The machine that runs make (CLAUDE.md section 5). Its commands show at
# this prompt on the page.
CONTROLLER = "controller"
LAB_VMS = ("ssc-node", "ssc-monitor", "ssc-attacker")
NODE_VARS = ROOT / "inventory" / "group_vars" / "node.yml"
ALL_VARS = ROOT / "inventory" / "group_vars" / "all.yml"
TODO = ROOT / "TODO.md"
INVENTORY = ROOT / "inventory" / "lab.yml"
MULTIPASS_LIST = ["multipass", "list", "--format", "json"]
# make demo-live rebuilds the page this often, in seconds.
LIVE_INTERVAL = 30

# (label, file in results/, note). Numbers come only from these files. A
# label that starts with "interim" is marked as interim.
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


def admin_user() -> str:
    return yaml.safe_load(ALL_VARS.read_text())["admin_user"]


def current_phase() -> str:
    """The phase TODO.md names as current, or "?" when it names none."""
    match = re.search(r"^Current phase: \*\*(\d+)\*\*", TODO.read_text(), re.M)
    return match.group(1) if match else "?"


def controller_dir() -> str:
    """The repo as a shell prompt shows it: under ~ when it is in the home directory."""
    try:
        return "~/" + ROOT.relative_to(Path.home()).as_posix()
    except ValueError:
        return ROOT.as_posix()


def indented_json(text: str) -> str:
    """JSON output indented for reading; anything else as it came."""
    try:
        return json.dumps(json.loads(text), indent=2)
    except ValueError:
        return text.rstrip("\n")


def controller_address() -> str:
    """The controller's lab address, from the generated inventory."""
    try:
        inventory = yaml.safe_load(INVENTORY.read_text())
        return str(inventory["all"]["vars"]["lab_controller_ip"])
    except (OSError, KeyError, TypeError, yaml.YAMLError):
        return "address not in inventory"


def phase2_command() -> str:
    """The pytest command a full run uses, with paths relative to the repo."""
    argv = pytest_argv()
    return shlex.join([os.path.relpath(argv[0], ROOT), *argv[1:]])


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_whole(path: Path, text: str) -> None:
    """Write a partial file, then rename it into place, so a reader never
    sees half a file."""
    partial = path.with_name(path.name + ".partial")
    path.parent.mkdir(parents=True, exist_ok=True)
    partial.write_text(text, encoding="utf-8")
    os.replace(partial, path)


# A process that already holds the lock on .lab/demo (the lab test) passes
# its descriptor here, and the run shares that lock instead of taking its own.
LOCK_FD_ENV = "SSC_DEMO_LOCK_FD"


class DirLock:
    """An exclusive flock on a directory, held until release(). Locking the
    directory itself leaves no lock file behind."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.fd: int | None = None
        self.owned = False

    def acquire(self) -> bool:
        """True once held; False when another process holds it."""
        inherited = os.environ.get(LOCK_FD_ENV)
        if inherited is not None:
            fd = int(inherited)
            if not os.path.samestat(os.fstat(fd), os.stat(self.directory)):
                raise OSError(f"{LOCK_FD_ENV}={inherited} is not {self.directory}")
        else:
            self.directory.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.directory, os.O_RDONLY)
            self.owned = True
        try:
            # On an inherited descriptor this succeeds at once: the lock
            # belongs to the open file the parent shared.
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            if self.owned:
                os.close(fd)
            return False
        self.fd = fd
        return True

    def release(self) -> None:
        # Never unlock an inherited descriptor: that would drop the parent's lock.
        if self.owned and self.fd is not None:
            os.close(self.fd)
        self.fd = None


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


@dataclass
class Row:
    name: str
    value: str
    # info; ok (the secure value); down (a VM that is not running); error; or
    # note (a line under the row above)
    kind: str = "info"
    badge: str = ""


@dataclass
class Prompt:
    command: str  # exactly what the demo ran, at the section's host
    raw: str = ""  # what it printed, for the page's expandable output


@dataclass
class Section:
    title: str
    host: str = ""  # where its commands run: CONTROLLER or NODE
    comment: str = ""  # shown when no command made the values
    lines: list[Row | Prompt] = field(default_factory=list)


@dataclass
class Phase2:
    passed: bool | None = None  # None: no result to show
    status: str = ""  # PASS, FAIL, or why there is no result
    detail: str = ""
    saved_at: str = ""


class Demo:
    def __init__(
        self,
        runner: Runner = run,
        out=sys.stdout,
        quick: bool = False,
        as_page: bool = False,
        open_page: bool = False,
        saved: Path | None = None,
        page: Path | None = None,
        clock: Callable[[], str] = utc_now,
        live: int | None = None,
    ) -> None:
        self.runner = runner
        self.out = out
        # The page shows the same data as --quick: it never runs the suites.
        self.quick = quick or as_page
        self.as_page = as_page
        self.open_page = open_page
        self.saved = saved or SAVED
        self.page = page or PAGE
        self.clock = clock
        # Seconds between rebuilds when make demo-live builds the page.
        self.live = live
        self.ok = True
        self.read_at = ""
        self.sections: list[Section] = []
        self.phase2_result = Phase2()
        # What the topology shows, read by the steps above.
        self.vm_info: dict[str, tuple[str, str]] = {}
        self.input_policy = ""
        self.fail2ban_state = "fail2ban not read"
        self.saved_text = ""  # the saved Phase 2 record, for the page

    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def heading(self, title: str, host: str = "", comment: str = "") -> None:
        self.sections.append(Section(title, host, comment))
        self.say(title)

    def prompt(self, command: str) -> Prompt:
        """Record the command that makes the next rows, for the page's prompt
        line. The text summary does not print it."""
        line = Prompt(command)
        self.sections[-1].lines.append(line)
        return line

    def row(self, name: str, value: str, kind: str = "info", badge: str = "") -> None:
        self.sections[-1].lines.append(Row(name, value, kind, badge))
        self.say(f"  {name:<16} {value}")

    def problem(self, name: str, text: str) -> None:
        self.ok = False
        self.row(name, f"ERROR: {text}", "error")

    def node(self, command: str) -> str | None:
        line = self.prompt(command)
        result = self.runner(ssh(command), None)
        if result.returncode != 0:
            line.raw = f"(exit {result.returncode}) {result.stderr.strip()}".strip()
            return None
        line.raw = indented_json(result.stdout)
        return result.stdout

    def vms(self) -> None:
        self.heading("Lab VMs (multipass list)", CONTROLLER)
        line = self.prompt(shlex.join(MULTIPASS_LIST))
        try:
            result = self.runner(MULTIPASS_LIST, None)
        except FileNotFoundError:
            self.problem("multipass", "not installed")
            return
        if result.returncode != 0:
            line.raw = result.stderr.strip()
            self.problem("multipass", (result.stderr.strip() or "list failed").splitlines()[0])
            return
        listed = {vm["name"]: vm for vm in json.loads(result.stdout)["list"]}
        # The page shows the lab VMs' entries only, never other VMs on the host.
        line.raw = json.dumps(
            {"list": [listed[name] for name in LAB_VMS if name in listed]}, indent=2
        )
        for name in LAB_VMS:
            vm = listed.get(name)
            if vm is None:
                self.vm_info[name] = ("not created", "")
                self.row(name, "not created", "down")
                continue
            self.vm_info[name] = (vm["state"], ", ".join(vm["ipv4"]))
            kind = "ok" if vm["state"] == "Running" else "down"
            self.row(name, f"{vm['state']:<9} {', '.join(vm['ipv4'])}", kind)

    def lynis(self) -> None:
        files = " and ".join(f"results/{name}" for _, name, _ in LYNIS)
        self.heading(
            f"Lynis hardening index on {NODE} (from results/)",
            comment=f"read from {files}; Lynis does not run here",
        )
        for label, name, note in LYNIS:
            badge = "interim" if label.startswith("interim") else ""
            path = ROOT / "results" / name
            if not path.exists():
                self.row(label, f"pending (no results/{name})", badge=badge)
            else:
                data = json.loads(path.read_text())
                self.row(
                    label,
                    f"{data['hardening_index']:<4} {data['timestamp']},"
                    f" Lynis {data['lynis_version']}, git {data['git_sha'][:7]} (results/{name})",
                    badge=badge,
                )
            if note:
                self.row("", note, "note")

    def sshd(self) -> None:
        dump = self.node(NODE_COMMANDS["sshd"])
        if dump is None:
            self.problem("sshd -T", "could not read")
            return
        values = dict(line.partition(" ")[::2] for line in dump.splitlines())
        secure = all(values.get(key) == "no" for key in SSHD_KEYS)
        self.row(
            "sshd -T",
            ", ".join(f"{key} {values.get(key, '?')}" for key in SSHD_KEYS),
            "ok" if secure else "info",
        )

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
                if hook == "input":
                    self.input_policy = "accept"
                self.row(f"policy {hook}", "no chain, so accept")
                continue
            # Secure when every chain but fail2ban's ban list drops by default.
            own = [c for c in found if c["table"] != "f2b-table"]
            drops = bool(own) and all(c["policy"] == "drop" for c in own)
            if hook == "input":
                self.input_policy = "drop" if drops else "accept"
            self.row(
                f"policy {hook}",
                ", ".join(
                    f"{c['policy']} ({c['family']} {c['table']}"
                    + (", fail2ban bans only)" if c["table"] == "f2b-table" else ")")
                    for c in found
                ),
                "ok" if drops else "info",
            )

    def fail2ban(self) -> None:
        status = self.node(NODE_COMMANDS["fail2ban"])
        if status is None:
            self.fail2ban_state = "fail2ban not running"
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
        self.fail2ban_state = f"fail2ban up, {n['Currently banned']} banned now"
        self.row(
            "fail2ban sshd",
            f"jail up; banned now {n['Currently banned']} (total {n['Total banned']}),"
            f" failed logins now {n['Currently failed']} (total {n['Total failed']})",
            "ok",
        )

    def mounts(self) -> None:
        for path in ("/tmp", "/dev/shm"):
            line = self.node(NODE_COMMANDS[path])
            if not line:
                self.problem(path, "not a mount point")
                continue
            options = set(line.split()[-1].split(","))
            secure = {"nosuid", "nodev", "noexec"} <= options
            self.row(path, " ".join(line.split()), "ok" if secure else "info")

    def sudo_rights(self) -> None:
        # One command per user, so each gets its own result line.
        for user in research_users():
            listing = self.node(SUDO_LIST.format(user=user))
            if listing is None:
                self.problem(f"sudo {user}", "could not list")
            elif "is not allowed to run sudo" in listing:
                self.row(f"sudo {user}", "no rights", "ok")
            else:
                self.ok = False
                self.row(f"sudo {user}", "HAS SUDO RIGHTS", "error")

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
        try:
            write_whole(self.saved, json.dumps(record, indent=2) + "\n")
        except OSError as err:
            self.ok = False
            self.say(f"  could not save it for QUICK=1: {err}")
            return
        self.say(f"  saved for QUICK=1 in {os.path.relpath(self.saved, ROOT)}")

    def phase2_saved(self) -> None:
        record, error = read_saved(self.saved)
        if record is None:
            self.ok = False
            self.phase2_result = Phase2(None, error)
            self.say(f"Phase 2 checks: {error}")
            return
        self.show_phase2(record["passed"], record["counts"], record["saved_at"])
        self.saved_text = json.dumps(record, indent=2)
        self.say(
            f"  saved {record['saved_at']} by the last full `make demo`; QUICK=1 did not rerun them"
        )

    def show_phase2(self, passed: bool, counts: dict[str, int], saved_at: str = "") -> None:
        self.ok = self.ok and passed
        left_out = counts.get("deselected", 0)
        detail = ", ".join(f"{n} {key}" for key, n in counts.items() if key != "deselected")
        status = "PASS" if passed else "FAIL"
        text = (
            f"{detail or 'no summary'}; {left_out} tests that change VM state left out,"
            " `pytest -m lab` runs them"
        )
        self.phase2_result = Phase2(passed, status, text, saved_at)
        self.say(f"Phase 2 checks: {status} ({text})")

    def write_page(self) -> bool:
        try:
            write_whole(self.page, render_page(self))
        except OSError as err:
            self.ok = False
            self.say(f"Could not write the page: {err}")
            return False
        self.say(f"Wrote {os.path.relpath(self.page, ROOT)}")
        if not self.open_page:
            return True
        try:
            opened = self.runner(["open", str(self.page)], None).returncode == 0
        except FileNotFoundError:
            opened = False
        if not opened:
            self.say("Could not run `open` (macOS only); open the page in a browser.")
        return True

    def main(self) -> int:
        """Run the demo; a run that writes into .lab/demo/ holds its lock."""
        if self.quick and not self.as_page:
            return self.run()
        directory = (self.page if self.as_page else self.saved).parent
        lock = DirLock(directory)
        try:
            held = lock.acquire()
        except (OSError, ValueError) as err:
            self.say(f"Could not lock {os.path.relpath(directory, ROOT)}: {err}")
            return 1
        if not held:
            self.say(
                f"Another demo run is writing {os.path.relpath(directory, ROOT)} (make demo,"
                " make demo-html or the lab test). Wait for it to end, then try again."
            )
            return 1
        try:
            return self.run()
        finally:
            lock.release()

    def run(self) -> int:
        self.collect()
        if self.as_page:
            self.write_page()
        return 0 if self.ok else 1

    def collect(self) -> None:
        """Read the lab and print the summary; the page is written apart."""
        self.read_at = self.clock()
        self.say("Secure Shared Compute Node: live lab summary (changes nothing on the VMs)")
        self.say(f"Live values read {self.read_at}")
        self.say()
        self.vms()
        self.say()
        self.lynis()
        self.say()
        self.heading(f"{NODE} now", NODE)
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


def summary_counts(line: str) -> dict[str, int]:
    """Counts from pytest's last line, such as "120 passed, 9 deselected in 80.1s"."""
    return {
        key: int(n)
        for n, key in re.findall(
            r"(\d+) (passed|failed|errors?|skipped|deselected|xfailed|xpassed)", line
        )
    }


# ---- the page (--html) ---------------------------------------------------

# Color tokens. Dark glass is the default; the light theme is a frosted
# version under prefers-color-scheme: light. tests/test_demo.py checks every
# text color against the panel (WCAG AA, 4.5:1), also where a panel sits over
# the brightest part of an ambient glow.
THEMES = {
    "dark": {
        "bg": "#05070c",
        "panel": "#0d1219",
        "line": "#ffffff",
        "text": "#e6edf3",
        "muted": "#8d98a8",
        "ok": "#56d364",
        "warn": "#e3b341",
        "bad": "#ff7b72",
        "who": "#8ae234",
        "where": "#79a8f2",
        "cmd": "#f0f6fc",
        "glow-1": "#14b8a6",
        "glow-2": "#7c3aed",
        "glow-3": "#2563eb",
        "chip-session": "#79c0ff",
        "chip-session-text": "#041120",
        "chip-pass": "#3fb950",
        "chip-pass-text": "#04130a",
        "chip-fail": "#f85149",
        "chip-fail-text": "#1c0402",
    },
    "light": {
        "bg": "#dde3ec",
        "panel": "#ffffff",
        "line": "#0f172a",
        "text": "#111827",
        "muted": "#4b5563",
        "ok": "#116329",
        "warn": "#7d4e00",
        "bad": "#b42318",
        "who": "#2f6a0a",
        "where": "#1f4fa0",
        "cmd": "#0b1220",
        "glow-1": "#5eead4",
        "glow-2": "#c4b5fd",
        "glow-3": "#93c5fd",
        "chip-session": "#0550ae",
        "chip-session-text": "#ffffff",
        "chip-pass": "#1a7f37",
        "chip-pass-text": "#ffffff",
        "chip-fail": "#cf222e",
        "chip-fail-text": "#ffffff",
    },
}
# How opaque the glass panel and the ambient glows are, per theme.
PANEL_ALPHA = {"dark": 0.62, "light": 0.60}
GLOW_ALPHA = {"dark": 0.32, "light": 0.6}
SHADOW = {"dark": "0, 0, 0", "light": "15, 23, 42"}
TEXT_TOKENS = ("text", "muted", "ok", "warn", "bad", "who", "where", "cmd")
CHIPS = ("chip-session", "chip-pass", "chip-fail")
# Local fonts only: the page loads nothing, so it looks the same offline.
MONO = '"SF Mono", Menlo, "JetBrains Mono", "DejaVu Sans Mono", monospace'


def rgba(color: str, alpha: float) -> str:
    red, green, blue = (int(color[i : i + 2], 16) for i in (1, 3, 5))
    return f"rgba({red}, {green}, {blue}, {alpha})"


def theme_css(name: str) -> str:
    """The custom properties for one theme."""
    t = THEMES[name]
    glow = GLOW_ALPHA[name]
    shadow = SHADOW[name]
    props = {key: value for key, value in t.items() if not key.startswith("glow")}
    props.update(
        {
            "panel-glass": rgba(t["panel"], PANEL_ALPHA[name]),
            "inset": rgba(t["line"], 0.03),
            "halo": rgba(t["where"], 0.35),
            "border": rgba(t["line"], 0.12),
            "highlight": rgba("#ffffff", 0.14 if name == "dark" else 0.85),
            "bar": rgba(t["line"], 0.04),
            "btn": rgba(t["line"], 0.08),
            "code-bg": rgba(t["line"], 0.07),
            "hover": rgba(t["line"], 0.06),
            "ok-tint": rgba(t["ok"], 0.12),
            "warn-tint": rgba(t["warn"], 0.14),
            "bad-tint": rgba(t["bad"], 0.12),
            "shadow": (
                f"0 1px 2px rgba({shadow}, 0.3), 0 18px 40px rgba({shadow}, 0.32),"
                f" 0 50px 100px rgba({shadow}, 0.28)"
                if name == "dark"
                else f"0 1px 2px rgba({shadow}, 0.08), 0 18px 40px rgba({shadow}, 0.12),"
                f" 0 50px 100px rgba({shadow}, 0.1)"
            ),
        }
    )
    for i in (1, 2, 3):
        props[f"glow-{i}"] = rgba(t[f"glow-{i}"], glow)
    return " ".join(f"--{key}: {value};" for key, value in props.items())


PAGE_RULES = """
* { box-sizing: border-box; }
html, body { background: var(--bg); }
body { margin: 0; min-height: 100vh; color: var(--text); font: 14px/1.55 var(--mono);
  overflow-x: hidden; -webkit-font-smoothing: antialiased; }
.glow { position: fixed; z-index: 0; width: 46vmax; height: 46vmax; border-radius: 50%;
  filter: blur(60px); pointer-events: none;
  animation: drift 48s ease-in-out infinite alternate; }
.g1 { top: -14vmax; left: -10vmax;
  background: radial-gradient(circle, var(--glow-1), transparent 65%); }
.g2 { top: 28vh; right: -16vmax;
  background: radial-gradient(circle, var(--glow-2), transparent 65%);
  animation-duration: 62s; animation-delay: -20s; }
.g3 { bottom: -20vmax; left: 18vw;
  background: radial-gradient(circle, var(--glow-3), transparent 65%);
  animation-duration: 56s; animation-delay: -35s; }
@keyframes drift {
  from { transform: translate3d(0, 0, 0) scale(1); }
  to { transform: translate3d(6vmax, 4vmax, 0) scale(1.12); }
}
main { position: relative; z-index: 1; max-width: 72rem; margin: 0 auto; padding: 40px 16px 32px; }
.window { overflow: hidden; border: 1px solid var(--border); border-radius: 14px;
  background: var(--panel-glass);
  -webkit-backdrop-filter: blur(22px) saturate(160%); backdrop-filter: blur(22px) saturate(160%);
  box-shadow: inset 0 1px 0 var(--highlight), var(--shadow); }
@supports not ((backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px))) {
  .window { background: var(--panel); }
}
.titlebar { display: grid; grid-template-columns: 1fr auto 1fr; align-items: center;
  min-height: 42px; padding: 0 10px 0 14px; border-bottom: 1px solid var(--border);
  background: var(--bar); }
.title { grid-column: 2; overflow: hidden; font-weight: 700; white-space: nowrap;
  text-overflow: ellipsis; }
.controls { grid-column: 3; justify-self: end; display: flex; gap: 8px; }
.controls svg { width: 24px; height: 24px; padding: 6px; border-radius: 50%;
  background: var(--btn); fill: none; stroke: var(--muted); stroke-width: 1.6;
  stroke-linecap: round; }
.screen { padding: 22px 24px 10px; }
.motd { margin: 0 0 26px; }
.eyebrow { margin: 0; color: var(--muted); }
h1 { margin: 2px 0 8px; font-size: 1.45em; line-height: 1.25; }
.lede { max-width: 50rem; margin: 0 0 14px; color: var(--muted); }
.overall { margin: 0 0 12px; }
.times { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 0; }
.times dt { color: var(--muted); }
.times dd { margin: 0; }
.block { margin: 0 0 22px; }
.block h2 { margin: 0 0 4px; color: var(--muted); font-size: 1em; font-weight: 400; }
.block h2::before { content: "# "; }
.comment { margin: 0 0 4px; color: var(--muted); }
.prompt { margin: 0; white-space: pre-wrap; overflow-wrap: break-word; }
.who { color: var(--who); font-weight: 700; }
.where { color: var(--where); font-weight: 700; }
.cmd { color: var(--cmd); }
.rows { display: grid; grid-template-columns: minmax(9rem, 13rem) 1fr; gap: 1px 12px;
  margin: 4px 0 10px; padding-left: 2ch; }
.rows dt, .rows dd { margin: 0; padding: 1px 6px; border-radius: 4px; }
.rows dt { color: var(--muted); }
.rows dd { white-space: pre-wrap; overflow-wrap: anywhere; }
.rows dd.ok { color: var(--ok); }
.rows dd.down { color: var(--bad); }
.rows .error { color: var(--bad); font-weight: 700; }
.rows dd.note { grid-column: 2; color: var(--warn); }
.badge { margin-left: 1ch; padding: 0 6px; border-radius: 4px; color: var(--warn);
  background: var(--warn-tint); font-weight: 700; }
.pill { display: inline-block; padding: 1px 10px; border-radius: 6px; font-weight: 700; }
.pass { color: var(--ok); background: var(--ok-tint); }
.fail { color: var(--bad); background: var(--bad-tint); }
.result { display: flex; flex-wrap: wrap; gap: 4px 12px; align-items: baseline;
  margin: 6px 0 4px 2ch; }
.meta { margin: 0 0 0 2ch; color: var(--muted); }
code { padding: 0 5px; border-radius: 4px; color: var(--cmd); background: var(--code-bg);
  font-family: inherit; }
.last { margin-top: 4px; }
.cursor { display: inline-block; width: 0.62em; height: 1.15em; vertical-align: text-bottom;
  background: var(--text); animation: blink 1.1s steps(1, end) infinite; }
@keyframes blink { 50% { opacity: 0; } }
.statusbar { display: flex; flex-wrap: wrap; align-items: center; gap: 2px 14px;
  min-height: 30px; padding: 4px 10px; border-top: 1px solid var(--border);
  background: var(--bar); }
.chip { padding: 0 8px; border-radius: 3px; font-weight: 700; }
.chip.session { color: var(--chip-session-text); background: var(--chip-session); }
.chip.pass { color: var(--chip-pass-text); background: var(--chip-pass); }
.chip.fail { color: var(--chip-fail-text); background: var(--chip-fail); }
.fill { flex: 1; }
.key { color: var(--muted); }
.foot { margin: 18px 4px 0; color: var(--muted); font-size: 0.9em; }
"""

# Last, so they win over every rule above: no motion when the system asks
# for less, and a one-column layout at phone width.
MEDIA_RULES = """
@media (prefers-reduced-motion: reduce) {
  .glow, .cursor, .link.flow, .up .dot, .stage.current { animation: none; }
}
@media (max-width: 640px) {
  .topo svg.wide { display: none; }
  .topo svg.tall { display: block; }
  .stages { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  details.raw { margin-left: 0; }
  body { font-size: 13px; }
  main { padding: 16px 16px 24px; }
  .screen { padding: 16px 14px 6px; }
  .titlebar { grid-template-columns: 1fr auto; }
  .title { grid-column: 1; }
  .controls { grid-column: 2; }
  .times { grid-template-columns: 1fr; gap: 0; }
  .times dd { margin-bottom: 4px; }
  .rows { grid-template-columns: 1fr; gap: 0; padding-left: 0; }
  .rows dd { margin-bottom: 6px; }
  .rows dd.note { grid-column: 1; }
  .result, .meta { margin-left: 0; }
  .fill { display: none; }
}
"""


def page_css() -> str:
    return (
        f":root {{ color-scheme: dark; {theme_css('dark')} --mono: {MONO}; }}\n"
        "@media (prefers-color-scheme: light) {\n"
        f"  :root {{ color-scheme: light; {theme_css('light')} }}\n"
        "}\n" + PAGE_RULES + TOPO_RULES + hover_rules() + MEDIA_RULES
    )


# Linux window buttons (minimize, maximize, close), drawn inline.
CONTROLS = (
    '<span class="controls" aria-hidden="true">'
    '<svg viewBox="0 0 16 16"><path d="M4.5 8h7"/></svg>'
    '<svg viewBox="0 0 16 16"><rect x="4.5" y="4.5" width="7" height="7" rx="0.5"/></svg>'
    '<svg viewBox="0 0 16 16"><path d="M5 5l6 6M11 5l-6 6"/></svg>'
    "</span>"
)


def prompt_html(host: str, command: str = "", cursor: bool = False) -> str:
    """One shell prompt line. The command is exactly what the demo ran."""
    e = html.escape
    if host == NODE:
        who, where = f"{admin_user()}@{NODE}", "~"
    else:
        who, where = CONTROLLER, controller_dir()
    if cursor:
        tail = ' <span class="cursor" aria-hidden="true"></span>'
    else:
        tail = f' <span class="cmd">{e(command)}</span>' if command else ""
    return (
        f'<p class="prompt{" last" if cursor else ""}"><span class="who">{e(who)}</span>:'
        f'<span class="where">{e(where)}</span>${tail}</p>'
    )


def render_rows(rows: list[Row]) -> str:
    e = html.escape
    items = []
    for row in rows:
        if row.kind == "note":
            items.append(f'<dd class="note">{e(row.value)}</dd>')
            continue
        badge = f' <span class="badge">{e(row.badge)}</span>' if row.badge else ""
        if row.kind == "error":
            items.append(
                f'<dt class="error">{e(row.name)}{badge}</dt><dd class="error">{e(row.value)}</dd>'
            )
            continue
        css = f' class="{row.kind}"' if row.kind in ("ok", "down") else ""
        items.append(f"<dt>{e(row.name)}{badge}</dt><dd{css}>{e(row.value)}</dd>")
    return "\n".join(['<dl class="rows">', *items, "</dl>"])


def render_section(section: Section) -> str:
    """A terminal block: the section's prompt lines, each with its rows."""
    e = html.escape
    parts = ['<section class="block">', f"<h2>{e(section.title)}</h2>"]
    if section.comment:
        parts.append(f'<p class="comment"># {e(section.comment)}</p>')
    rows: list[Row] = []
    raw = ""

    def flush() -> None:
        # A command's rows, then its raw output, which opens on a click.
        if rows:
            parts.append(render_rows(rows))
            rows.clear()
        if raw:
            parts.append(raw_details("raw output", raw))

    for line in section.lines:
        if isinstance(line, Prompt):
            flush()
            parts.append(prompt_html(section.host, line.command))
            raw = line.raw
        else:
            rows.append(line)
    flush()
    parts.append("</section>")
    return "\n".join(parts)


def raw_details(label: str, text: str) -> str:
    """Output that opens and closes with no script: a <details> element."""
    return (
        f'<details class="raw"><summary>{html.escape(label)}</summary>'
        f"<pre>{html.escape(text)}</pre></details>"
    )


def code_spans(text: str) -> str:
    """Escape text, then show `command` spans as code."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(text))


def render_phase2(demo: "Demo") -> str:
    e = html.escape
    result = demo.phase2_result
    parts = ['<section class="block">', "<h2>Phase 2 checks</h2>"]
    if result.passed is None:
        parts.append(
            f'<p class="result"><span class="pill fail">{code_spans(result.status)}</span></p>'
        )
    else:
        css = "pass" if result.passed else "fail"
        parts += [
            '<p class="comment"># the last full make demo ran:</p>',
            prompt_html(CONTROLLER, phase2_command()),
            f'<p class="result"><span class="pill {css}">{e(result.status)}</span>'
            f" <span>{code_spans(result.detail)}</span></p>",
            f'<p class="meta">Saved {e(result.saved_at)} by the last full <code>make demo</code>.'
            " This page did not rerun them; <code>make demo</code> does.</p>",
        ]
        if demo.saved_text:
            name = os.path.relpath(demo.saved, ROOT)
            parts.append(raw_details(f"the saved result, {name}", demo.saved_text.rstrip("\n")))
    parts.append("</section>")
    return "\n".join(parts)


def render_statusbar(demo: "Demo") -> str:
    """A tmux-style status line: session, window, host, phase, read time, result."""
    e = html.escape
    state = "pass" if demo.ok else "fail"
    live = (
        [f'<span class="live">Live: refreshes every {demo.live} s</span>']
        if demo.live is not None
        else []
    )
    return "\n".join(
        [
            '<div class="statusbar">',
            '<span class="chip session">[ssc-lab]</span>',
            f"<span>0:{e(NODE)}*</span>",
            '<span class="fill"></span>',
            *live,
            f'<span><span class="key">host</span> {e(NODE)}</span>',
            f'<span><span class="key">phase</span> {e(current_phase())}</span>',
            f'<span><span class="key">read</span> {e(demo.read_at)}</span>',
            f'<span class="chip {state}">{state.upper()}</span>',
            "</div>",
        ]
    )


# ---- the topology and the build stages -------------------------------------

# Build stages in the order TODO.md lists their phases. The names are the
# page's labels; each stage's state comes from TODO.md.
STAGES = (
    (0, "Lab"),
    (1, "Baseline audit"),
    (2, "Hardening"),
    (3, "Isolation"),
    (4, "Monitoring"),
    (5, "Detection"),
    (6, "Attack tests"),
    (7, "Evidence"),
)
# The flows that later phases add, and the TODO task that builds each.
PLANNED = {"monitoring": ("4", "P4.3"), "egress": ("5", "P5.5")}


@dataclass
class Stage:
    phase: int
    name: str
    state: str  # done, current, or later
    ticked: int
    total: int


def todo_stages(text: str) -> list[Stage]:
    """Each build stage's state from TODO.md: before the current phase is
    done, the current phase is current, the rest are later."""
    current = re.search(r"^Current phase: \*\*(\d+)\*\*", text, re.M)
    now = int(current.group(1)) if current else -1
    boxes: dict[int, list[bool]] = {}
    phase = None
    for line in text.splitlines():
        heading = re.match(r"## Phase (\d+):", line)
        if heading:
            phase = int(heading.group(1))
            boxes[phase] = []
        elif phase is not None and re.match(r"- \[[ x]\] P\d", line):
            boxes[phase].append(line.startswith("- [x]"))
    stages = []
    for number, name in STAGES:
        state = "done" if number < now else "current" if number == now else "later"
        found = boxes.get(number, [])
        stages.append(Stage(number, name, state, sum(found), len(found)))
    return stages


def task_ticked(text: str, task: str) -> bool:
    return re.search(rf"^- \[x\] {re.escape(task)}\b", text, re.M) is not None


# Line icons, drawn around (0, 0) in the page's stroke style.
ICONS = {
    # a laptop: screen and base
    "controller": '<rect x="-22" y="-20" width="44" height="28" rx="3"/>'
    '<path d="M-29 12h58l-4 7h-50z"/>',
    # a server tower: drive bays and a power light
    "ssc-node": '<rect x="-15" y="-24" width="30" height="48" rx="3"/>'
    '<path d="M-8 -14h16M-8 -7h16"/><circle cx="0" cy="12" r="2.2"/>',
    # a server with a small chart on its face
    "ssc-monitor": '<rect x="-23" y="-19" width="46" height="38" rx="3"/>'
    '<path d="M-15 9l8-9 6 5 12-12"/>',
    # a server with a warning mark
    "ssc-attacker": '<rect x="-23" y="-17" width="46" height="34" rx="3"/>'
    '<path d="M-15 -7h13M-15 1h9"/><path d="M13 -9l10 17h-20z"/>'
    '<path d="M13 -3v5M13 5.5v0.5"/>',
}
SHIELD = '<path d="M0 -13l11 4v7c0 8-5 13-11 15-6-2-11-7-11-15v-7z"/>'
CHECK = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 8.5l3 3 6-7"/></svg>'


@dataclass
class Machine:
    key: str  # controller, node, monitor or attacker: the CSS class suffix
    name: str
    address: str
    state: str  # Running, Stopped, ..., "not created"; the controller is "runs make"

    @property
    def up(self) -> bool:
        return self.state in ("Running", "runs make")


@dataclass
class Topology:
    machines: dict[str, Machine]  # by key
    input_policy: str  # the node's own input policy: drop, accept, or "" if unread
    fail2ban: str  # a short fail2ban state for the attack line's label
    built: dict[str, bool]  # PLANNED key -> its TODO task is ticked


# Per layout: each machine's place and where its labels go ("right" or
# "below"), then every line's path. Coordinates are in viewBox units.
WIDE = {
    "view": "0 36 1000 336",
    "place": {
        "controller": (120, 200, "below"),
        "monitor": (560, 72, "right"),
        "node": (560, 200, "right"),
        "attacker": (560, 330, "right"),
    },
    "ssh": {
        "monitor": "M156 196 C330 196 360 72 516 72",
        "node": "M156 200 L516 200",
        "attacker": "M156 204 C330 204 360 330 516 330",
    },
    "ssh_label": (330, 186, "middle"),
    "attack_to_shield": "M560 304 L560 262",
    "attack_through": "M560 304 L560 226",
    "shield": (560, 250),
    "attack_label": (580, 272, "start"),
    "monitoring": "M560 174 L560 98",
    "monitoring_label": (546, 140, "end"),
    "egress": "M730 200 L888 200",
    "egress_label": (800, 188, "middle"),
    "internet": (930, 200),
}
TALL = {
    "view": "0 0 360 700",
    "place": {
        "controller": (180, 52, "below"),
        "monitor": (75, 236, "below"),
        "attacker": (285, 236, "below"),
        "node": (180, 452, "below"),
    },
    "ssh": {
        "monitor": "M164 128 C130 160 90 180 80 206",
        "node": "M180 128 L180 420",
        "attacker": "M196 128 C230 160 270 180 280 206",
    },
    "ssh_label": (188, 170, "start"),
    "attack_to_shield": "M285 330 C285 365 262 385 240 398",
    "attack_through": "M285 330 C285 380 240 420 206 440",
    "shield": (232, 406),
    "attack_label": (350, 366, "end"),
    "monitoring": "M150 430 C110 400 75 370 75 330",
    "monitoring_label": (12, 392, "start"),
    "egress": "M180 540 L180 618",
    "egress_label": (190, 584, "start"),
    "internet": (180, 650),
}
LAYOUTS = {"wide": WIDE, "tall": TALL}
VM_KEYS = {"ssc-node": "node", "ssc-monitor": "monitor", "ssc-attacker": "attacker"}


def svg_text(x: float, y: float, anchor: str, lines: list[tuple[str, str]]) -> str:
    """A text block of (css class, text) lines, 16 units apart."""
    e = html.escape
    spans = "".join(
        f'<tspan x="{x}" dy="{0 if i == 0 else 16}" class="{css}">{e(text)}</tspan>'
        for i, (css, text) in enumerate(lines)
    )
    return f'<text x="{x}" y="{y}" text-anchor="{anchor}">{spans}</text>'


def machine_svg(machine: Machine, x: int, y: int, labels: str) -> str:
    state = "up" if machine.up else "down"
    if labels == "right":
        text = svg_text(
            x + 40,
            y - 12,
            "start",
            [("name", machine.name), ("sub", machine.address), ("sub", machine.state)],
        )
        hit = f'<rect class="hit" x="{x - 34}" y="{y - 34}" width="210" height="70"/>'
    else:
        text = svg_text(
            x,
            y + 44,
            "middle",
            [("name", machine.name), ("sub", machine.address), ("sub", machine.state)],
        )
        hit = f'<rect class="hit" x="{x - 80}" y="{y - 34}" width="160" height="114"/>'
    return (
        f'<g class="machine m-{machine.key} {state}">{hit}'
        f'<g class="icon" transform="translate({x} {y})">{ICONS[machine.name]}</g>'
        f'<circle class="dot" cx="{x + 27}" cy="{y - 22}" r="5"/>{text}</g>'
    )  # fmt: skip


def link_svg(path: str, *classes: str) -> str:
    return f'<path class="link {" ".join(classes)}" d="{path}"/>'


def topology_svg(name: str, topo: Topology) -> str:
    layout = LAYOUTS[name]
    m = topo.machines
    parts = []
    # Controller to each VM: SSH and Ansible. It moves only while the VM runs.
    for key in ("monitor", "node", "attacker"):
        moving = "flow" if m[key].up else "still"
        parts.append(link_svg(layout["ssh"][key], "ssh", "to-controller", f"to-{key}", moving))
    x, y, anchor = layout["ssh_label"]
    parts.append(svg_text(x, y, anchor, [("tag", "SSH and Ansible")]))
    # The attacker's traffic: it stops at the node's shield while the input
    # policy is drop, and goes through when it is not.
    blocked = topo.input_policy == "drop"
    moving = "flow" if m["attacker"].up and m["node"].up else "still"
    path = layout["attack_to_shield"] if blocked else layout["attack_through"]
    parts.append(
        link_svg(path, "attack", "to-attacker", "to-node", moving, "" if blocked else "through")
    )
    x, y, anchor = layout["attack_label"]
    policy = f"input policy {topo.input_policy}" if topo.input_policy else "input policy not read"
    parts.append(svg_text(x, y, anchor, [("tag", policy), ("tag", topo.fail2ban)]))
    # Flows later phases add: dashed and gray, never moving.
    for key, path_key, label_key, text in (
        ("monitoring", "monitoring", "monitoring_label", "metrics"),
        ("egress", "egress", "egress_label", "egress filter"),
    ):
        phase, _ = PLANNED[key]
        targets = ("to-node", "to-monitor") if key == "monitoring" else ("to-node",)
        parts.append(link_svg(layout[path_key], "planned", *targets))
        note = (
            f"{text}: built in Phase {phase}, not read here"
            if topo.built[key]
            else (f"{text}: Phase {phase}")
        )
        x, y, anchor = layout[label_key]
        parts.append(svg_text(x, y, anchor, [("tag", note)]))
    x, y = layout["internet"]
    parts.append(
        f'<g class="outside"><rect x="{x - 38}" y="{y - 16}" width="76" height="32" rx="8"/>'
        f"{svg_text(x, y + 5, 'middle', [('sub', 'internet')])}</g>"
    )
    x, y = layout["shield"]
    parts.append(
        f'<g class="shield{"" if blocked else " open"}" transform="translate({x} {y})">{SHIELD}</g>'
    )
    for key, (x, y, labels) in layout["place"].items():
        parts.append(machine_svg(m[key], x, y, labels))
    return (
        f'<svg class="{name}" viewBox="{layout["view"]}" role="img"'
        ' aria-label="Lab topology: the controller, the three lab VMs and the flows between them">'
        + "".join(parts)
        + "</svg>"
    )


def render_stages(stages: list[Stage]) -> str:
    e = html.escape
    items = []
    for stage in stages:
        mark = CHECK if stage.state == "done" else ""
        count = f"{stage.ticked} of {stage.total} tasks" if stage.total else "no tasks listed"
        label = {"done": "finished", "current": "in progress", "later": "not started"}[stage.state]
        items.append(
            f'<li class="stage {stage.state}"><span class="mark">{mark}</span>'
            f'<span class="phase">Phase {stage.phase}</span>'
            f'<span class="name">{e(stage.name)}</span>'
            f'<span class="count">{count}</span><span class="state">{label}</span></li>'
        )
    return "\n".join(['<ol class="stages">', *items, "</ol>"])


TOPO_RULES = """
.panel { margin: 0 0 22px; padding: 12px 14px 14px; border: 1px solid var(--border);
  border-radius: 12px; background: var(--inset); }
.panel h2 { margin: 0 0 8px; color: var(--muted); font-size: 1em; font-weight: 400; }
.panel h2::before { content: "# "; }
.topo svg { display: block; width: 100%; height: auto; }
.topo svg.tall { display: none; max-width: 420px; margin: 0 auto; }
.topo text { font-family: var(--mono); font-size: 13px; fill: var(--text);
  paint-order: stroke; stroke: var(--panel); stroke-width: 5px; stroke-linejoin: round; }
.topo .name { font-weight: 700; }
.topo .sub, .topo .tag { fill: var(--muted); }
.topo .tag { font-size: 12px; }
.hit { fill: transparent; }
.machine .icon { fill: none; stroke: var(--text); stroke-width: 1.6; stroke-linejoin: round;
  stroke-linecap: round; }
.machine.down .icon { opacity: 0.4; }
.machine.down .name { fill: var(--muted); }
.dot { stroke: none; }
.up .dot { fill: var(--ok); animation: pulse 2.6s ease-in-out infinite; }
.down .dot { fill: var(--bad); }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
.link { fill: none; stroke: var(--where); stroke-width: 1.7; opacity: 0.85;
  transition: opacity 0.2s, stroke-width 0.2s; }
.link.flow { stroke-dasharray: 6 8; animation: flow 1.4s linear infinite; }
.link.still { stroke: var(--muted); opacity: 0.4; }
.link.attack { stroke: var(--warn); }
.link.attack.through { stroke: var(--bad); }
.link.attack.still { stroke: var(--muted); }
.link.planned { stroke: var(--muted); stroke-dasharray: 3 6; opacity: 0.75; }
@keyframes flow { to { stroke-dashoffset: -28; } }
.shield path { fill: var(--ok-tint); stroke: var(--ok); stroke-width: 1.7; }
.shield.open path { fill: none; stroke: var(--bad); }
.outside rect { fill: none; stroke: var(--muted); stroke-dasharray: 3 4; }
.legend { margin: 6px 0 0; color: var(--muted); }
.stages { display: grid; grid-template-columns: repeat(8, minmax(0, 1fr)); gap: 8px;
  margin: 0; padding: 0; list-style: none; }
.stage { display: flex; flex-direction: column; gap: 2px; padding: 8px 10px;
  border: 1px solid var(--border); border-radius: 10px; }
.stage .mark { display: block; width: 18px; height: 18px; border: 1.5px solid var(--muted);
  border-radius: 50%; }
.stage .mark svg { display: block; width: 100%; height: 100%; fill: none;
  stroke: var(--chip-pass-text); stroke-width: 2.2; stroke-linecap: round;
  stroke-linejoin: round; }
.stage .name { font-weight: 700; line-height: 1.3; }
.stage .phase, .stage .count, .stage .state { color: var(--muted); font-size: 0.86em; }
.stage.current .state { color: var(--where); }
.stage.done { background: var(--ok-tint); border-color: transparent; }
.stage.done .mark { border-color: var(--chip-pass); background: var(--chip-pass); }
.stage.current { border-color: var(--where); animation: halo 3.2s ease-in-out infinite; }
.stage.current .mark { border-color: var(--where); box-shadow: inset 0 0 0 4px var(--where); }
.stage.later { border-style: dashed; }
.stage.later .name { color: var(--muted); font-weight: 400; }
@keyframes halo {
  0%, 100% { box-shadow: 0 0 0 0 var(--halo); }
  50% { box-shadow: 0 0 18px 2px var(--halo); }
}
.rows dt:hover, .rows dt:hover + dd, .rows dd:hover, .rows dt:has(+ dd:hover) {
  background: var(--hover); }
details.raw { margin: 2px 0 8px 2ch; }
details.raw summary { color: var(--muted); cursor: pointer; }
details.raw pre { max-height: 22rem; margin: 4px 0 0; padding: 8px 10px; overflow: auto;
  border-radius: 8px; background: var(--code-bg); white-space: pre-wrap;
  overflow-wrap: anywhere; }
.live { color: var(--where); font-weight: 700; }
"""


def hover_rules() -> str:
    """Hovering a machine brings its own lines forward and fades the rest."""
    rules = [".topo:has(.machine:hover) .link { opacity: 0.18; }"]
    for key in ("controller", "node", "monitor", "attacker"):
        rules.append(f".topo:has(.m-{key}:hover) .to-{key} {{ opacity: 1; stroke-width: 2.6; }}")
    return "\n".join(rules) + "\n"


def build_topology(demo: "Demo", todo: str) -> Topology:
    """The machines and flows from what this run read, and TODO.md."""
    machines = {"controller": Machine("controller", CONTROLLER, controller_address(), "runs make")}
    for name, key in VM_KEYS.items():
        state, address = demo.vm_info.get(name, ("not read", ""))
        machines[key] = Machine(key, name, address or "no address", state)
    built = {key: task_ticked(todo, task) for key, (_, task) in PLANNED.items()}
    return Topology(machines, demo.input_policy, demo.fail2ban_state, built)


def render_topology(demo: "Demo", todo: str) -> str:
    topo = build_topology(demo, todo)
    return "\n".join(
        [
            '<section class="panel topo">',
            "<h2>Lab topology (machines from multipass list, ssc-node values below)</h2>",
            topology_svg("wide", topo),
            topology_svg("tall", topo),
            '<p class="legend">Moving lines: traffic that flows now. Dashed gray: not built'
            " yet. Dimmed: a VM that is not running. Hover a machine to pick out its lines.</p>",
            "</section>",
            '<section class="panel">',
            "<h2>Build stages (from TODO.md)</h2>",
            render_stages(todo_stages(todo)),
            "</section>",
        ]
    )


def render_page(demo: "Demo") -> str:
    """The summary as one HTML page: every value escaped, nothing loaded."""
    e = html.escape
    saved_at = demo.phase2_result.saved_at or "no saved result"
    if demo.ok:
        overall = '<span class="pill pass">Every check worked and passed</span>'
    else:
        overall = (
            '<span class="pill fail">Something failed or could not be read:'
            " see the rows in red</span>"
        )
    # Only a page that make demo-live keeps rebuilding reloads itself.
    refresh = (
        [f'<meta http-equiv="refresh" content="{demo.live}">'] if demo.live is not None else []
    )
    if demo.live is not None:
        made_by = (
            "Written by <code>make demo-live</code> (<code>scripts/demo.py --html --live</code>),"
            f" which rebuilds it every {demo.live} s until Ctrl+C."
        )
    else:
        made_by = "Written by <code>make demo-html</code> (<code>scripts/demo.py --html</code>)."
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            *refresh,
            "<title>SSC Lab Console</title>",
            f"<style>\n{page_css()}</style>",
            "</head>",
            "<body>",
            '<div class="glow g1" aria-hidden="true"></div>',
            '<div class="glow g2" aria-hidden="true"></div>',
            '<div class="glow g3" aria-hidden="true"></div>',
            "<main>",
            '<div class="window">',
            f'<div class="titlebar"><span class="title">{e(admin_user())}@{e(NODE)}: ~</span>'
            f"{CONTROLS}</div>",
            '<div class="screen">',
            '<header class="motd">',
            '<p class="eyebrow">Secure Shared Compute Node</p>',
            "<h1>Live lab summary</h1>",
            '<p class="lede">Read-only: making this page changed nothing on any VM.'
            f" The Lynis numbers come from files in <code>results/</code>; the {e(NODE)}"
            " rows were read live over SSH.</p>",
            f'<p class="overall">{overall}</p>',
            '<dl class="times">',
            f"<dt>Live values read (UTC)</dt><dd>{e(demo.read_at)}</dd>",
            f"<dt>Phase 2 checks saved (UTC)</dt><dd>{e(saved_at)}</dd>",
            "</dl>",
            "</header>",
            render_topology(demo, TODO.read_text()),
            *(render_section(section) for section in demo.sections),
            render_phase2(demo),
            prompt_html(NODE, cursor=True),
            "</div>",
            render_statusbar(demo),
            "</div>",
            f'<footer class="foot">{made_by} One file with no scripts that loads'
            " nothing from elsewhere, so it works offline.</footer>",
            "</main>",
            "</body>",
            "</html>",
            "",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only summary of the live lab.")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="show the saved Phase 2 result instead of running the suites",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help=f"also write the --quick summary as a page, {os.path.relpath(PAGE, ROOT)}",
    )
    parser.add_argument("--open", action="store_true", help="open the page with `open`")
    parser.add_argument(
        "--live",
        action="store_true",
        help=f"rebuild the page every {LIVE_INTERVAL} s until Ctrl+C (make demo-live)",
    )
    # Shorter rounds for the lab test.
    parser.add_argument("--interval", type=int, default=LIVE_INTERVAL, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.open and not args.html:
        parser.error("--open needs --html")
    if args.live and not args.html:
        parser.error("--live needs --html")
    if args.interval < 1:
        parser.error("--interval must be at least 1")
    if args.live:
        return live_main(args.interval, args.open)
    return Demo(quick=args.quick, as_page=args.html, open_page=args.open).main()


# ---- live mode (make demo-live) ------------------------------------------


def live(make_demo: Callable[[bool], Demo], interval: int, stop: threading.Event, out) -> int:
    """Rebuild the page every `interval` seconds until `stop` is set.

    Each round is a --html run, so it is as read-only on the VMs as make
    demo-html. A round that Ctrl+C cuts short is not written: the page left
    behind is always a whole round. Returns the last written round's code."""
    last = 1
    first = True
    while not stop.is_set():
        demo = make_demo(first)
        demo.collect()
        if stop.is_set():
            break
        if not demo.write_page():
            return 1
        last = 0 if demo.ok else 1
        print(
            f"live: wrote {os.path.relpath(demo.page, ROOT)}, values read {demo.read_at},"
            f" {'PASS' if demo.ok else 'FAIL'}",
            file=out,
            flush=True,
        )
        first = False
        if stop.wait(interval):
            break
    print("live: stopped; the page shows the last whole round", file=out, flush=True)
    return last


def live_main(interval: int, open_page: bool) -> int:
    """make demo-live: hold the .lab/demo lock and rebuild until Ctrl+C."""
    lock = DirLock(PAGE.parent)
    try:
        held = lock.acquire()
    except (OSError, ValueError) as err:
        print(f"Could not lock {os.path.relpath(PAGE.parent, ROOT)}: {err}")
        return 1
    if not held:
        print(
            f"Another demo run is writing {os.path.relpath(PAGE.parent, ROOT)} (make demo,"
            " make demo-html or the lab test). Wait for it to end, then try again."
        )
        return 1
    print(f"live: rebuilding the page every {interval} s; Ctrl+C stops", flush=True)

    def make_demo(first: bool) -> Demo:
        # The summary text of each round is not printed; one line per round is.
        return Demo(out=io.StringIO(), as_page=True, open_page=open_page and first, live=interval)

    # Ctrl+C sets the event: the round in progress ends, and the loop stops.
    stop = threading.Event()
    previous = signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        return live(make_demo, interval, stop, sys.stdout)
    finally:
        signal.signal(signal.SIGINT, previous)
        lock.release()


if __name__ == "__main__":
    sys.exit(main())
