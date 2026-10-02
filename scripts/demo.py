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
nothing loaded from elsewhere, so it works offline. --open then opens the
page with macOS `open`. Those two files in .lab/demo/ are the only ones the
demo writes; --quick alone writes none.

A run that writes into .lab/demo/ (a full run, or --html) holds an
exclusive lock on that directory for the whole run, so two runs never write
it at once. One that finds the lock taken stops at once and writes nothing.
--quick alone only reads, so it takes no lock.

tests/test_demo.py checks all of this, and that a real run leaves the repo
(apart from those files) and the VMs as they were.

Usage: scripts/demo.py [--quick | --html [--open]]
Exit 0 when every check worked and passed.
"""

import argparse
import fcntl
import html
import json
import os
import re
import subprocess
import sys
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
LAB_VMS = ("ssc-node", "ssc-monitor", "ssc-attacker")
NODE_VARS = ROOT / "inventory" / "group_vars" / "node.yml"

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
    kind: str = "info"  # info, error, or note (a line under the row above)
    badge: str = ""


@dataclass
class Section:
    title: str
    rows: list[Row] = field(default_factory=list)


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
        self.ok = True
        self.read_at = ""
        self.sections: list[Section] = []
        self.phase2_result = Phase2()

    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def heading(self, title: str) -> None:
        self.sections.append(Section(title))
        self.say(title)

    def row(self, name: str, value: str, kind: str = "info", badge: str = "") -> None:
        self.sections[-1].rows.append(Row(name, value, kind, badge))
        self.say(f"  {name:<16} {value}")

    def problem(self, name: str, text: str) -> None:
        self.ok = False
        self.row(name, f"ERROR: {text}", "error")

    def node(self, command: str) -> str | None:
        result = self.runner(ssh(command), None)
        if result.returncode != 0:
            return None
        return result.stdout

    def vms(self) -> None:
        self.heading("Lab VMs (multipass list)")
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
        self.heading(f"Lynis hardening index on {NODE} (from results/)")
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
        granted = False
        for user in research_users():
            listing = self.node(SUDO_LIST.format(user=user))
            if listing is None:
                self.problem("sudo rights", f"could not list {user}")
                return
            if "is not allowed to run sudo" in listing:
                rights.append(f"{user}: none")
            else:
                granted = True
                rights.append(f"{user}: HAS SUDO RIGHTS")
        if granted:
            self.ok = False
        self.row("sudo rights", ", ".join(rights), "error" if granted else "info")

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

    def write_page(self) -> None:
        try:
            write_whole(self.page, render_page(self))
        except OSError as err:
            self.ok = False
            self.say(f"Could not write the page: {err}")
            return
        self.say(f"Wrote {os.path.relpath(self.page, ROOT)}")
        if not self.open_page:
            return
        try:
            opened = self.runner(["open", str(self.page)], None).returncode == 0
        except FileNotFoundError:
            opened = False
        if not opened:
            self.say("Could not run `open` (macOS only); open the page in a browser.")

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
        self.read_at = self.clock()
        self.say("Secure Shared Compute Node: live lab summary (changes nothing on the VMs)")
        self.say(f"Live values read {self.read_at}")
        self.say()
        self.vms()
        self.say()
        self.lynis()
        self.say()
        self.heading(f"{NODE} now")
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
        if self.as_page:
            self.write_page()
        return 0 if self.ok else 1


def summary_counts(line: str) -> dict[str, int]:
    """Counts from pytest's last line, such as "120 passed, 9 deselected in 80.1s"."""
    return {
        key: int(n)
        for n, key in re.findall(
            r"(\d+) (passed|failed|errors?|skipped|deselected|xfailed|xpassed)", line
        )
    }


# ---- the page (--html) ---------------------------------------------------

# Colors are tokens, set again for a dark system theme. System fonts only:
# the page loads nothing, so it looks the same offline.
PAGE_CSS = """
:root {
  color-scheme: light dark;
  --bg: #f5f6f8; --card: #ffffff; --text: #1c2230; --muted: #586174;
  --border: #dde1e8; --code: #eef0f4;
  --ok: #17663a; --ok-bg: #e3f3e8; --bad: #a8261b; --bad-bg: #fbe9e7;
  --warn: #7a4f00; --warn-bg: #fdf0cf;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1116; --card: #161a21; --text: #e4e7ec; --muted: #9aa2b1;
    --border: #2a303b; --code: #1f242d;
    --ok: #6fd08c; --ok-bg: #133020; --bad: #ff8f84; --bad-bg: #3b1714;
    --warn: #f0c35a; --warn-bg: #3a2c0b;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.5 var(--sans); }
main { max-width: 56rem; margin: 0 auto; padding: 32px 16px 48px; }
header { margin-bottom: 24px; }
.eyebrow { margin: 0; color: var(--muted); font-size: 0.8rem; letter-spacing: 0.06em;
  text-transform: uppercase; }
h1 { margin: 4px 0 8px; font-size: 1.6rem; line-height: 1.2; }
.lede { margin: 0 0 16px; color: var(--muted); max-width: 44rem; }
.pill { display: inline-block; padding: 2px 10px; border-radius: 999px; font-weight: 700; }
.pass { color: var(--ok); background: var(--ok-bg); }
.fail { color: var(--bad); background: var(--bad-bg); }
.overall { margin: 0 0 16px; }
.times { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 0;
  font-size: 0.9rem; }
.times dt { color: var(--muted); }
.times dd { margin: 0; font-family: var(--mono); }
section { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
  padding: 16px 20px; margin: 0 0 16px; }
h2 { margin: 0 0 12px; font-size: 1rem; }
.rows { display: grid; grid-template-columns: minmax(7rem, 11rem) 1fr; gap: 6px 16px;
  margin: 0; }
.rows dt { color: var(--muted); }
.rows dd { margin: 0; font-family: var(--mono); font-size: 0.88rem; white-space: pre-wrap;
  overflow-wrap: anywhere; }
.rows dd.note { grid-column: 2; font-family: var(--sans); color: var(--warn); }
.rows .error { color: var(--bad); font-weight: 600; }
.badge { display: inline-block; margin-left: 6px; padding: 0 8px; border-radius: 999px;
  font-size: 0.75rem; font-weight: 600; color: var(--warn); background: var(--warn-bg); }
.result { margin: 0 0 8px; display: flex; flex-wrap: wrap; gap: 8px 12px;
  align-items: baseline; }
.meta { margin: 0; color: var(--muted); font-size: 0.88rem; }
code { font-family: var(--mono); font-size: 0.88em; background: var(--code); padding: 1px 5px;
  border-radius: 4px; }
footer { color: var(--muted); font-size: 0.85rem; margin-top: 24px; }
@media (max-width: 560px) {
  .rows { grid-template-columns: 1fr; gap: 2px; }
  .rows dd { margin-bottom: 8px; }
  .rows dd.note { grid-column: 1; }
}
"""


def render_section(section: Section) -> str:
    e = html.escape
    items = []
    for row in section.rows:
        if row.kind == "note":
            items.append(f'<dd class="note">{e(row.value)}</dd>')
            continue
        badge = f' <span class="badge">{e(row.badge)}</span>' if row.badge else ""
        css = ' class="error"' if row.kind == "error" else ""
        items.append(f"<dt{css}>{e(row.name)}{badge}</dt><dd{css}>{e(row.value)}</dd>")
    return "\n".join(
        ["<section>", f"<h2>{e(section.title)}</h2>", '<dl class="rows">', *items, "</dl>",
         "</section>"]
    )  # fmt: skip


def code_spans(text: str) -> str:
    """Escape text, then show `command` spans as code."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(text))


def render_page(demo: Demo) -> str:
    """The summary as one HTML page: every value escaped, nothing loaded."""
    e = html.escape
    result = demo.phase2_result
    css = {True: "pass", False: "fail"}.get(result.passed, "fail")
    saved_at = result.saved_at or "no saved result"
    if demo.ok:
        overall = '<span class="pill pass">Every check worked and passed</span>'
    else:
        overall = (
            '<span class="pill fail">Something failed or could not be read:'
            " see the rows in red</span>"
        )
    if result.passed is None:
        phase2 = f'<p class="result"><span class="pill fail">{code_spans(result.status)}</span></p>'
    else:
        phase2 = (
            f'<p class="result"><span class="pill {css}">{e(result.status)}</span>'
            f" <span>{code_spans(result.detail)}</span></p>\n"
            f'<p class="meta">Saved {e(saved_at)} by the last full <code>make demo</code>.'
            " This page did not rerun them; <code>make demo</code> does.</p>"
        )
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            "<title>SSC Lab Summary</title>",
            f"<style>{PAGE_CSS}</style>",
            "</head>",
            "<body>",
            "<main>",
            "<header>",
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
            *(render_section(section) for section in demo.sections),
            '<section class="phase2">',
            "<h2>Phase 2 checks</h2>",
            phase2,
            "</section>",
            "<footer>Written by <code>make demo-html</code> (<code>scripts/demo.py --html</code>)."
            " One file with no scripts that loads nothing from elsewhere, so it works"
            " offline.</footer>",
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
    args = parser.parse_args(argv)
    if args.open and not args.html:
        parser.error("--open needs --html")
    return Demo(quick=args.quick, as_page=args.html, open_page=args.open).main()


if __name__ == "__main__":
    sys.exit(main())
