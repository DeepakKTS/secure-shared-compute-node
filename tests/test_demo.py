"""Tests for scripts/demo.py (make demo), which must change nothing on the VMs.

The unit tests feed it canned command output and check what it runs and
prints, and that the only file it writes is the saved Phase 2 result (none
with --quick, only the page with --html). The lab test runs the real `make
demo`, then `make demo QUICK=1`, then live mode for two rounds, then the page
run, and checks that the repo (apart from those files) and every lab VM are
as they were before each.
"""

import ast
import fcntl
import html
import io
import json
import os
import re
import select
import signal
import subprocess
import threading
import time
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

REAL_SAVED = demo.SAVED
REAL_PAGE = demo.PAGE
FULL_AT = "2026-01-02T03:04:05Z"
QUICK_AT = "2026-01-02T09:00:00Z"
PHASE2_PASS = (
    "Phase 2 checks: PASS (227 passed; 17 tests that change VM state left out,"
    " `pytest -m lab` runs them)"
)


@pytest.fixture(autouse=True)
def saved_result(tmp_path: Path, monkeypatch) -> Path:
    # Unit tests never touch the real saved result in .lab/demo/.
    path = tmp_path / "demo" / "phase2.json"
    monkeypatch.setattr(demo, "SAVED", path)
    return path


@pytest.fixture(autouse=True)
def page_path(tmp_path: Path, monkeypatch) -> Path:
    # Nor the real page.
    path = tmp_path / "demo" / "index.html"
    monkeypatch.setattr(demo, "PAGE", path)
    return path


def saved_record(**changes) -> str:
    record = {
        "saved_at": FULL_AT,
        "passed": True,
        "counts": {"passed": 227, "deselected": 17},
        "returncode": 0,
        "suites": list(demo.PHASE2_SUITES),
        "marker": "lab and not changes_state",
    }
    return json.dumps({**record, **changes})


def completed(argv, rc: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(argv, rc, out, err)


class FakeLab:
    """Stands in for demo.run: answers from canned output, records every call."""

    def __init__(
        self,
        node=None,
        pytest_out="227 passed, 17 deselected in 90.00s",
        pytest_rc=0,
        multipass=None,
    ):
        self.node = {**NODE_OUTPUT, **(node or {})}
        self.pytest = completed([], pytest_rc, f"....\n{pytest_out}\n")
        self.multipass = multipass or MULTIPASS
        self.calls: list[tuple[list[str], dict | None]] = []

    def __call__(self, argv, env):
        self.calls.append((argv, env))
        if argv[0] == "multipass":
            return completed(argv, 0, json.dumps(self.multipass))
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
        if argv[0] == "open":
            return completed(argv)
        raise AssertionError(f"demo ran an unexpected command: {argv}")


def run_demo(lab: FakeLab, at: str = FULL_AT, **flags: bool) -> tuple[int, str]:
    out = io.StringIO()
    rc = demo.Demo(runner=lab, out=out, clock=lambda: at, **flags).main()
    return rc, out.getvalue()


def changed_keys(before: dict, after: dict) -> set[str]:
    return {key for key in set(before) | set(after) if before.get(key) != after.get(key)}


# Claude Code rewrites this file (and so changes .claude's mtime) when the
# owner approves a command with "don't ask again", at any moment. demo.py
# never runs Claude Code. Found by the B2 runs in .lab/flaky/.
CLAUDE_LOCAL = {ROOT / ".claude", ROOT / ".claude" / "settings.local.json"}


def repo_state(root: Path = ROOT) -> dict[str, tuple[int, int, int]]:
    """(mode, size, mtime) of every file and directory in the repo, ignored
    ones included, so a write, a new file or a removed one all show. Left
    out: .lab/audit (Claude Code's own hooks append to it), .git (an editor's
    git integration can write there; demo.py runs no git command, see
    test_demo_runs_only_multipass_ssh_and_pytest), Claude Code's local
    settings (CLAUDE_LOCAL) and Finder's .DS_Store."""
    state = {}
    for top, dirs, files in os.walk(root):
        here = Path(top)
        dirs[:] = [d for d in dirs if here / d not in (ROOT / ".git", LAB / "audit")]
        for name in [*dirs, *files]:
            if name == ".DS_Store" or here / name in CLAUDE_LOCAL:
                continue
            path = here / name
            st = path.lstat()
            state[str(path.relative_to(root))] = (st.st_mode, st.st_size, st.st_mtime_ns)
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
        PHASE2_PASS,
    ):
        assert line in text.splitlines(), (line, text)
    assert "other-vm" not in text
    assert text.splitlines()[1] == f"Live values read {FULL_AT}"


def test_lynis_index_comes_from_results() -> None:
    data = json.loads((ROOT / "results" / "lynis-before.json").read_text())
    _, text = run_demo(FakeLab())
    row = next(line for line in text.splitlines() if line.startswith("  before "))
    assert row.split()[1] == str(data["hardening_index"])
    assert data["git_sha"][:7] in row and "results/lynis-before.json" in row


def test_missing_lynis_result_shows_pending(monkeypatch) -> None:
    monkeypatch.setattr(demo, "LYNIS", (("after", "lynis-no-such-file.json", ""),))
    _, text = run_demo(FakeLab())
    assert "  after            pending (no results/lynis-no-such-file.json)" in text.splitlines()


def test_interim_audit_is_labelled_as_not_comparable() -> None:
    _, text = run_demo(FakeLab())
    lines = text.splitlines()
    row = next(i for i, line in enumerate(lines) if line.startswith("  interim-p2 "))
    assert "results/lynis-interim-p2.json" in lines[row]
    assert lines[row + 1] == (
        "                   interim: not comparable to the final after-audit"
        " until P7.0a to P7.0c are done"
    )


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


def test_saved_result_lives_in_lab_demo() -> None:
    assert REAL_SAVED == LAB / "demo" / "phase2.json"


def test_full_run_saves_the_phase2_result(saved_result: Path) -> None:
    _, text = run_demo(FakeLab())
    assert json.loads(saved_result.read_text()) == json.loads(saved_record())
    # Renamed into place: no partial file is left beside it.
    assert [p.name for p in saved_result.parent.iterdir()] == ["phase2.json"]
    assert text.splitlines()[-2] == PHASE2_PASS
    assert text.splitlines()[-1].startswith("  saved for QUICK=1 in ")


def test_full_run_writes_only_the_saved_result(saved_result: Path) -> None:
    before = repo_state()
    run_demo(FakeLab())
    assert differences(before, repo_state()) == []
    assert saved_result.is_file()


def test_quick_run_shows_the_saved_result_and_runs_no_tests(saved_result: Path) -> None:
    run_demo(FakeLab())
    lab = FakeLab(pytest_out="1 failed in 1.00s", pytest_rc=1)  # would FAIL if it ran
    rc, text = run_demo(lab, quick=True, at=QUICK_AT)
    assert rc == 0, text
    assert [argv[0] for argv, _ in lab.calls if argv[0] not in ("multipass", "ssh")] == []
    lines = text.splitlines()
    assert lines[1] == f"Live values read {QUICK_AT}"
    assert lines[-2:] == [
        PHASE2_PASS,
        f"  saved {FULL_AT} by the last full `make demo`; QUICK=1 did not rerun them",
    ]


def test_quick_run_writes_no_file(saved_result: Path) -> None:
    run_demo(FakeLab())
    before = repo_state(), repo_state(saved_result.parent)
    run_demo(FakeLab(), quick=True, at=QUICK_AT)
    assert differences(before[0], repo_state()) == []
    assert differences(before[1], repo_state(saved_result.parent)) == []


def test_quick_run_without_a_saved_result_fails() -> None:
    rc, text = run_demo(FakeLab(), quick=True)
    assert rc == 1
    assert text.splitlines()[-1] == (
        "Phase 2 checks: no saved result; run `make demo` once without QUICK=1"
    )


def test_quick_run_shows_a_saved_failure() -> None:
    run_demo(FakeLab(pytest_out="1 failed, 226 passed, 17 deselected in 90.00s", pytest_rc=1))
    rc, text = run_demo(FakeLab(), quick=True, at=QUICK_AT)
    assert rc == 1
    assert text.splitlines()[-2].startswith("Phase 2 checks: FAIL (1 failed, 226 passed;"), text


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{not json", "saved result unreadable"),
        ("[1, 2]", "saved result unreadable"),
        (saved_record(passed="yes"), "saved result unreadable"),
        (saved_record(saved_at="yesterday"), "saved result unreadable"),
        (saved_record(counts={"passed": "227"}), "saved result unreadable"),
        (saved_record(suites=["tests/test_base.py"]), "saved result is for other suites"),
        (saved_record(marker="lab"), "saved result is for other suites"),
    ],
)
def test_quick_run_refuses_a_saved_result_it_cannot_trust(
    saved_result: Path, content: str, message: str
) -> None:
    saved_result.parent.mkdir(parents=True)
    saved_result.write_text(content)
    rc, text = run_demo(FakeLab(), quick=True)
    assert rc == 1
    assert text.splitlines()[-1] == (
        f"Phase 2 checks: {message}; run `make demo` once without QUICK=1"
    )


def test_flags_reach_the_demo(monkeypatch) -> None:
    seen = []
    monkeypatch.setattr(
        demo.Demo, "main", lambda self: seen.append((self.quick, self.as_page, self.open_page)) or 0
    )
    for argv in ([], ["--quick"], ["--html"], ["--html", "--open"]):
        assert demo.main(argv) == 0
    # --html always uses the saved result, like --quick.
    assert seen == [
        (False, False, False),
        (True, False, False),
        (True, True, False),
        (True, True, True),
    ]
    with pytest.raises(SystemExit):
        demo.main(["--open"])


# ---- the page (make demo-html) ---------------------------------------------


def run_page(page_path: Path, lab: FakeLab | None = None, **flags: bool) -> tuple[int, str, str]:
    """A full run saves the Phase 2 result, then the page run shows it."""
    run_demo(FakeLab())
    rc, text = run_demo(lab or FakeLab(), at=QUICK_AT, as_page=True, **flags)
    return rc, text, page_path.read_text()


def test_page_path_is_in_lab_demo() -> None:
    assert REAL_PAGE == LAB / "demo" / "index.html"


def test_page_run_writes_only_the_page(saved_result: Path, page_path: Path) -> None:
    run_demo(FakeLab())
    repo_before, demo_before = repo_state(), repo_state(saved_result.parent)
    rc, text = run_demo(FakeLab(), at=QUICK_AT, as_page=True)
    assert rc == 0, text
    assert differences(repo_before, repo_state()) == []
    # The page, renamed into place: no partial file, and the saved result as it was.
    assert changed_keys(demo_before, repo_state(saved_result.parent)) == {"index.html"}
    assert page_path.parent == saved_result.parent


def test_page_shows_the_same_data_as_quick_mode() -> None:
    run_demo(FakeLab())
    _, quick = run_demo(FakeLab(), at=QUICK_AT, quick=True)
    lab = FakeLab()
    _, page = run_demo(lab, at=QUICK_AT, as_page=True)
    assert page.splitlines()[:-1] == quick.splitlines()
    assert page.splitlines()[-1].startswith("Wrote ")
    # No suite run, and no `open` unless asked.
    assert [argv[0] for argv, _ in lab.calls if argv[0] not in ("multipass", "ssh")] == []


def test_page_is_opened_only_after_it_is_written(page_path: Path) -> None:
    lab = FakeLab()
    run_page(page_path, lab, open_page=True)
    assert lab.calls[-1][0] == ["open", str(page_path)]
    assert [argv for argv, _ in lab.calls if argv[0] == "open"] == [["open", str(page_path)]]


def test_page_failing_to_open_is_reported(page_path: Path) -> None:
    lab = FakeLab()
    original = lab.__call__

    def no_open(argv, env):
        if argv[0] == "open":
            raise FileNotFoundError("open")
        return original(argv, env)

    rc, text, _ = run_page(page_path, no_open, open_page=True)
    assert rc == 0
    assert text.splitlines()[-1].startswith("Could not run `open`")


def test_page_loads_nothing_and_has_light_and_dark_themes(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    assert page.startswith("<!doctype html>")
    assert '<meta charset="utf-8">' in page
    # Nothing that fetches: no scripts, links, images, frames, imports or URLs.
    for pattern in (r"<script", r"<link", r"<img", r"<iframe", r"@import", r"url\(", r"//",
                    r"\bsrc=", r"\bhref="):  # fmt: skip
        assert not re.search(pattern, page, re.I), pattern
    # Dark glass by default, a light frosted version for a light system theme.
    assert re.search(r":root \{ color-scheme: dark; --bg: #", page)
    assert re.search(
        r"@media \(prefers-color-scheme: light\) \{\s+:root \{ color-scheme: light;", page
    )


def test_page_shows_when_the_data_was_collected(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    assert f"<dt>Live values read (UTC)</dt><dd>{QUICK_AT}</dd>" in page
    assert f"<dt>Phase 2 checks saved (UTC)</dt><dd>{FULL_AT}</dd>" in page
    assert f"Saved {FULL_AT} by the last full <code>make demo</code>." in page


def test_page_marks_the_interim_lynis_index_as_interim(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    data = json.loads((ROOT / "results" / "lynis-interim-p2.json").read_text())
    row = re.search(r'<dt>interim-p2 <span class="badge">interim</span></dt><dd>([^<]*)</dd>', page)
    assert row, page
    assert row.group(1).split()[0] == str(data["hardening_index"])
    assert (
        '<dd class="note">interim: not comparable to the final after-audit'
        " until P7.0a to P7.0c are done</dd>"
    ) in page
    assert "<dt>before</dt>" in page  # the baseline gets no badge


def test_page_escapes_what_the_lab_returns(page_path: Path) -> None:
    sshd = "passwordauthentication <b>no</b>\npermitrootlogin no\nkbdinteractiveauthentication no\n"
    _, _, page = run_page(page_path, FakeLab(node={"sudo -n sshd -T": sshd}))
    assert "passwordauthentication &lt;b&gt;no&lt;/b&gt;" in page
    assert "<b>" not in page


def test_page_shows_command_spans_as_code(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    assert "change VM state left out, <code>pytest -m lab</code> runs them</span>" in page
    # Raw command output keeps its own characters (fail2ban prints "`- Actions").
    assert "`" not in re.sub(r"<pre>.*?</pre>", "", page, flags=re.S)


def test_page_shows_failures_in_red(saved_result: Path, page_path: Path) -> None:
    run_demo(FakeLab(pytest_out="1 failed, 226 passed, 17 deselected in 90.00s", pytest_rc=1))
    lab = FakeLab()
    lab.node = {}
    rc, _ = run_demo(lab, at=QUICK_AT, as_page=True)
    page = page_path.read_text()
    assert rc == 1
    assert '<span class="pill fail">Something failed or could not be read' in page
    assert '<dt class="error">sshd -T</dt><dd class="error">ERROR: could not read</dd>' in page
    assert '<span class="pill fail">FAIL</span> <span>1 failed, 226 passed;' in page


def commands_demo_runs() -> set[str]:
    """Every command the demo runs, as the page shows it."""
    return {
        "multipass list --format json",
        *EXPECTED_NODE_COMMANDS.values(),
        *(demo.SUDO_LIST.format(user=user) for user in demo.research_users()),
        demo.phase2_command(),
    }


def test_page_prompts_show_only_commands_the_demo_runs(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    shown = [html.unescape(c) for c in re.findall(r'<span class="cmd">([^<]*)</span>', page)]
    assert set(shown) <= commands_demo_runs(), set(shown) - commands_demo_runs()
    # Every one of them is shown, each at the prompt of the host it ran on.
    assert set(shown) == commands_demo_runs()
    node_prompt = (
        f'<span class="who">{demo.admin_user()}@ssc-node</span>:<span class="where">~</span>$'
    )
    for command in EXPECTED_NODE_COMMANDS.values():
        assert f'{node_prompt} <span class="cmd">{html.escape(command)}</span>' in page, command
    assert '<span class="who">controller</span>' in page
    # Lynis does not run: its block names the files instead of a command.
    assert "# read from results/lynis-before.json and results/lynis-interim-p2.json" in page


def test_page_is_a_linux_terminal_window(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    title = re.search(r'<span class="title">([^<]*)</span>', page).group(1)
    assert title == f"{demo.admin_user()}@ssc-node: ~"
    assert page.count('class="cursor"') == 1
    # The cursor sits at the end of the last prompt, after every block.
    last = page.index('<p class="prompt last">')
    assert page.rindex('<p class="prompt') == last
    assert last < page.index('class="cursor"') < page.index('<div class="statusbar">')


def test_status_bar_shows_host_phase_read_time_and_result(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    bar = page[page.index('<div class="statusbar">') :].split("</div>", 1)[0]
    phase = re.search(r"^Current phase: \*\*(\d+)\*\*", (ROOT / "TODO.md").read_text(), re.M)
    assert '<span class="key">host</span> ssc-node' in bar
    assert f'<span class="key">phase</span> {phase.group(1)}' in bar
    assert f'<span class="key">read</span> {QUICK_AT}' in bar
    assert '<span class="chip pass">PASS</span>' in bar


def test_one_failed_check_turns_the_page_red(page_path: Path) -> None:
    # Everything passes but one node command, which cannot be read.
    run_demo(FakeLab())
    lab = FakeLab()
    del lab.node["sudo -n fail2ban-client status sshd"]
    rc, _ = run_demo(lab, at=QUICK_AT, as_page=True)
    page = page_path.read_text()
    assert rc == 1
    assert (
        '<dt class="error">fail2ban sshd</dt><dd class="error">ERROR: jail not running</dd>' in page
    )
    assert '<span class="pill fail">Something failed or could not be read' in page
    assert '<span class="chip fail">FAIL</span>' in page and "chip pass" not in page
    # The other rows keep their own colors.
    assert '<dd class="ok">passwordauthentication no, permitrootlogin no' in page


def test_secure_values_are_green_and_a_missing_vm_red(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    for value in (
        "Running   192.0.2.2",
        "passwordauthentication no, permitrootlogin no, kbdinteractiveauthentication no",
        "accept (inet f2b-table, fail2ban bans only), drop (inet ssc_filter)",
        "tmpfs rw,nosuid,nodev,noexec,size=524288k",
        "alice: none, bob: none",
    ):
        assert f'<dd class="ok">{value}</dd>' in page, value
    assert '<dt>ssc-attacker</dt><dd class="down">not created</dd>' in page
    # Output has no chain yet (egress filtering is Phase 5): no green.
    assert "<dt>policy output</dt><dd>no chain, so accept</dd>" in page


def test_page_uses_only_local_monospace_fonts(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    assert demo.MONO == '"SF Mono", Menlo, "JetBrains Mono", "DejaVu Sans Mono", monospace'
    fonts = re.findall(r"font(?:-family)?:\s*([^;}]+)", page)
    assert fonts, "no font rules"
    for value in fonts:
        assert "var(--mono)" in value or value.strip() == "inherit", value
    assert f"--mono: {demo.MONO};" in page


def test_glass_has_a_solid_fallback_and_motion_can_be_turned_off(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    assert "backdrop-filter: blur(" in page and "-webkit-backdrop-filter: blur(" in page
    fallback = re.search(r"@supports not \(\(backdrop-filter[^{]*\{([^}]*)\}", page)
    assert fallback and "background: var(--panel);" in fallback.group(1)
    reduced = re.search(r"@media \(prefers-reduced-motion: reduce\) \{(.*?)\n\}", page, re.S)
    assert reduced and ".cursor" in reduced.group(1) and ".glow" in reduced.group(1)
    assert "animation: none;" in reduced.group(1)


def luminance(color: str) -> float:
    def channel(value: int) -> float:
        c = value / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    red, green, blue = (int(color[i : i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)


def contrast(one: str, two: str) -> float:
    high, low = sorted((luminance(one), luminance(two)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def over(top: str, alpha: float, under: str) -> str:
    """The color `top` at `alpha` makes over `under`."""
    mix = [
        round(alpha * int(top[i : i + 2], 16) + (1 - alpha) * int(under[i : i + 2], 16))
        for i in (1, 3, 5)
    ]
    return "#" + "".join(f"{c:02x}" for c in mix)


@pytest.mark.parametrize("theme", sorted(demo.THEMES))
def test_text_colors_meet_wcag_aa(theme: str) -> None:
    t = demo.THEMES[theme]
    # The glass panel over the page, and over the brightest point of each glow.
    backs = [t["panel"], over(t["panel"], demo.PANEL_ALPHA[theme], t["bg"])]
    for i in (1, 2, 3):
        glow = over(t[f"glow-{i}"], demo.GLOW_ALPHA[theme], t["bg"])
        backs.append(over(t["panel"], demo.PANEL_ALPHA[theme], glow))
    for token in demo.TEXT_TOKENS:
        for back in backs:
            assert contrast(t[token], back) >= 4.5, (theme, token, back)
    for chip in demo.CHIPS:
        assert contrast(t[f"{chip}-text"], t[chip]) >= 4.5, (theme, chip)


def test_page_has_no_emoji_dashes_or_ai_wording(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    assert page.isascii(), "no emoji, no em or en dashes, no other symbols"
    for word in ("generated", " ai ", "ai-", "powered", "seamless", "robust", "leverage"):
        assert word not in page.lower(), word


# ---- topology, stages, raw output, live mode (B3b) -------------------------

ALL_UP = {
    "list": [
        {"name": "ssc-node", "state": "Running", "ipv4": ["192.0.2.2"]},
        {"name": "ssc-monitor", "state": "Running", "ipv4": ["192.0.2.3"]},
        {"name": "ssc-attacker", "state": "Running", "ipv4": ["192.0.2.4"]},
        {"name": "other-vm", "state": "Running", "ipv4": ["192.0.2.9"]},
    ]
}


def with_attacker(state: str) -> dict:
    listing = json.loads(json.dumps(ALL_UP))
    listing["list"][2]["state"] = state
    if state != "Running":
        listing["list"][2]["ipv4"] = []
    return listing


def links(page: str) -> list[set[str]]:
    """The class set of every topology line in the wide drawing."""
    wide = page[page.index('<svg class="wide"') :].split("</svg>", 1)[0]
    return [set(c.split()) for c in re.findall(r'<path class="link ([^"]*)"', wide)]


def test_topology_shows_each_machine_from_multipass(page_path: Path) -> None:
    _, _, page = run_page(page_path, FakeLab(multipass=ALL_UP))
    for svg in ("wide", "tall"):
        drawing = page[page.index(f'<svg class="{svg}"') :].split("</svg>", 1)[0]
        for key, name, address in (
            ("node", "ssc-node", "192.0.2.2"),
            ("monitor", "ssc-monitor", "192.0.2.3"),
            ("attacker", "ssc-attacker", "192.0.2.4"),
        ):
            group = re.search(rf'<g class="machine m-{key} up">(.*?)</text></g>', drawing)
            assert group, (svg, key)
            assert f'class="name">{name}</tspan>' in group.group(1)
            assert f'class="sub">{address}</tspan>' in group.group(1)
            assert 'class="sub">Running</tspan>' in group.group(1)
        assert '<g class="machine m-controller up">' in drawing
    assert "other-vm" not in page.split("<details", 1)[0]


def test_a_stopped_attacker_is_dimmed_and_nothing_to_it_moves(page_path: Path) -> None:
    _, _, page = run_page(page_path, FakeLab(multipass=with_attacker("Stopped")))
    assert '<g class="machine m-attacker down">' in page
    assert 'class="sub">Stopped</tspan>' in page
    for classes in links(page):
        if "to-attacker" in classes:
            assert "flow" not in classes and "still" in classes, classes
    # The other VMs still move.
    assert any({"to-node", "ssh", "flow"} <= c for c in links(page))


def test_flows_that_are_not_built_never_move(page_path: Path) -> None:
    _, _, page = run_page(page_path, FakeLab(multipass=ALL_UP))
    planned = [c for c in links(page) if "planned" in c]
    assert len(planned) == 2
    assert all("flow" not in c for c in planned)
    assert "metrics: Phase 4" in page and "egress filter: Phase 5" in page


def test_attack_traffic_stops_at_the_shield_while_input_drops(page_path: Path) -> None:
    _, _, page = run_page(page_path, FakeLab(multipass=ALL_UP))
    (attack,) = [c for c in links(page) if "attack" in c]
    assert "flow" in attack and "through" not in attack
    assert '<g class="shield" transform=' in page
    assert "input policy drop" in page and "fail2ban up, 0 banned now" in page


def test_attack_traffic_goes_through_when_input_accepts(page_path: Path) -> None:
    chains = json.loads(json.dumps(CHAINS))
    chains["nftables"][1]["chain"]["policy"] = "accept"
    lab = FakeLab(node={"sudo -n nft -j list chains": json.dumps(chains)}, multipass=ALL_UP)
    _, _, page = run_page(page_path, lab)
    (attack,) = [c for c in links(page) if "attack" in c]
    assert "through" in attack
    assert '<g class="shield open"' in page and "input policy accept" in page


def test_stages_come_from_todo(tmp_path: Path, monkeypatch, page_path: Path) -> None:
    todo = tmp_path / "TODO.md"
    todo.write_text(
        "Current phase: **4**\n\n## Phase 0: Bootstrap\n- [x] P0.1 a\n- [x] Exit: x\n"
        "## Phase 3: Isolation\n- [x] P3.1 a\n- [ ] P3.3 b\n"
        "## Phase 4: Monitoring\n- [x] P4.1 a\n- [x] P4.3 prometheus\n- [ ] P4.5 c\n"
    )
    monkeypatch.setattr(demo, "TODO", todo)
    stages = demo.todo_stages(todo.read_text())
    assert [s.state for s in stages] == ["done"] * 4 + ["current"] + ["later"] * 3
    assert (stages[0].ticked, stages[0].total) == (1, 1)  # the Exit line is not a task
    assert (stages[3].ticked, stages[3].total) == (1, 2)
    _, _, page = run_page(page_path, FakeLab(multipass=ALL_UP))
    current = '<li class="stage current"><span class="mark"></span><span class="phase">Phase 4'
    assert current in page
    # P4.3 is ticked, so monitoring counts as built, but the page never
    # checks it live, so the line still does not move.
    assert "metrics: built in Phase 4, not read here" in page
    assert all("flow" not in c for c in links(page) if "planned" in c)


def test_raw_output_opens_and_closes_without_scripts(page_path: Path) -> None:
    _, _, page = run_page(page_path)
    raw = re.findall(r'<details class="raw"><summary>([^<]*)</summary><pre>(.*?)</pre>', page, re.S)
    # One per command, and the saved Phase 2 result.
    assert len(raw) == len(commands_demo_runs())
    texts = [html.unescape(text) for _, text in raw]
    assert any("passwordauthentication no" in t for t in texts)
    assert any('"name": "ssc-node"' in t for t in texts)
    assert not any("other-vm" in t for t in texts), "only the lab VMs' entries"
    assert any(summary.startswith("the saved result, ") for summary, _ in raw)


def test_hover_highlights_lines_and_rows() -> None:
    css = demo.page_css()
    for key in ("controller", "node", "monitor", "attacker"):
        assert f".topo:has(.m-{key}:hover) .to-{key}" in css
    assert ".rows dt:hover + dd" in css


def test_reduced_motion_stops_every_animation() -> None:
    css = demo.page_css()
    # Every rule that starts an animation (not one that sets it to none).
    animated = set(re.findall(r"([^{}\n]+)\{[^{}]*animation:\s*(?!none\b)[a-z]", css))
    assert animated, "no animations found"
    reduced = re.search(r"@media \(prefers-reduced-motion: reduce\) \{\s*([^{]+)\{", css)
    stopped = {s.strip() for s in reduced.group(1).split(",")}
    for selectors in animated:
        for selector in selectors.split(","):
            assert selector.strip() in stopped, selector


def test_phones_get_the_tall_drawing() -> None:
    css = demo.page_css()
    phone = css[css.index("@media (max-width: 640px)") :]
    assert ".topo svg.wide { display: none; }" in phone
    assert ".topo svg.tall { display: block; }" in phone


def test_only_a_live_page_refreshes(page_path: Path) -> None:
    _, _, static = run_page(page_path)
    assert "http-equiv" not in static and "Live:" not in static
    run_demo(FakeLab())
    demo.Demo(runner=FakeLab(), out=io.StringIO(), as_page=True, live=30).main()
    live = page_path.read_text()
    assert '<meta http-equiv="refresh" content="30">' in live
    assert '<span class="live">Live: refreshes every 30 s</span>' in live
    assert "make demo-live" in live


def test_live_rebuilds_until_stopped_and_drops_a_cut_round(page_path: Path) -> None:
    run_demo(FakeLab())
    stop = threading.Event()
    times = iter(["2026-01-02T09:00:00Z", "2026-01-02T09:00:30Z", "2026-01-02T09:01:00Z"])
    made: list[bool] = []

    def make_demo(first: bool) -> demo.Demo:
        made.append(first)
        if len(made) == 3:
            stop.set()  # as Ctrl+C would, while the third round reads the lab
        return demo.Demo(
            runner=FakeLab(), out=io.StringIO(), as_page=True, live=30, clock=lambda: next(times)
        )

    out = io.StringIO()
    rc = demo.live(make_demo, 0, stop, out)
    lines = out.getvalue().splitlines()
    assert rc == 0
    assert made == [True, False, False]
    assert [line.split(",")[1] for line in lines[:2]] == [
        " values read 2026-01-02T09:00:00Z",
        " values read 2026-01-02T09:00:30Z",
    ]
    assert lines[-1].startswith("live: stopped")
    # The third round was cut short and not written: the page is round two.
    page = page_path.read_text()
    assert "<dt>Live values read (UTC)</dt><dd>2026-01-02T09:00:30Z</dd>" in page


def test_live_mode_refuses_while_another_run_writes(page_path: Path) -> None:
    fd = hold_lock(page_path.parent)
    try:
        assert demo.live_main(1, False) == 1
    finally:
        os.close(fd)
    assert not page_path.exists()


def test_live_needs_html() -> None:
    with pytest.raises(SystemExit):
        demo.main(["--live"])


def test_page_without_a_saved_result_says_so(page_path: Path) -> None:
    rc, _ = run_demo(FakeLab(), as_page=True)
    page = page_path.read_text()
    assert rc == 1
    assert (
        '<span class="pill fail">no saved result; run <code>make demo</code> once without'
        " QUICK=1</span>"
    ) in page
    assert "<dt>Phase 2 checks saved (UTC)</dt><dd>no saved result</dd>" in page


def test_page_that_cannot_be_written_is_an_error(page_path: Path) -> None:
    page_path.mkdir(parents=True)  # a directory where the page should go
    rc, text = run_demo(FakeLab(), as_page=True)
    assert rc == 1
    assert text.splitlines()[-1].startswith("Could not write the page: ")


# ---- the lock on .lab/demo -------------------------------------------------


def hold_lock(directory: Path) -> int:
    """Lock the directory the way another demo run would."""
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory, os.O_RDONLY)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def lock_is_free(directory: Path) -> bool:
    fd = os.open(directory, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
    finally:
        os.close(fd)


@pytest.mark.parametrize("flags", [{}, {"as_page": True}], ids=["full", "page"])
def test_a_writing_run_stops_while_another_holds_the_lock(
    saved_result: Path, page_path: Path, flags: dict
) -> None:
    fd = hold_lock(saved_result.parent)
    try:
        lab = FakeLab()
        rc, text = run_demo(lab, **flags)
    finally:
        os.close(fd)
    assert rc == 1
    assert text.startswith("Another demo run is writing "), text
    assert lab.calls == [], "nothing runs while the lock is taken"
    assert not saved_result.exists() and not page_path.exists()


def test_quick_run_takes_no_lock(saved_result: Path) -> None:
    run_demo(FakeLab())
    fd = hold_lock(saved_result.parent)
    try:
        rc, text = run_demo(FakeLab(), quick=True, at=QUICK_AT)
    finally:
        os.close(fd)
    assert rc == 0, text


def test_a_run_releases_its_lock(saved_result: Path) -> None:
    run_demo(FakeLab())
    assert lock_is_free(saved_result.parent)


def test_a_run_shares_a_lock_its_parent_passes(saved_result: Path, monkeypatch) -> None:
    fd = hold_lock(saved_result.parent)
    monkeypatch.setenv(demo.LOCK_FD_ENV, str(fd))
    try:
        rc, text = run_demo(FakeLab())
        assert rc == 0, text
        # The parent's lock is still held after the run.
        assert not lock_is_free(saved_result.parent)
    finally:
        os.close(fd)


def test_a_passed_descriptor_for_another_path_is_refused(
    saved_result: Path, tmp_path: Path, monkeypatch
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    fd = os.open(other, os.O_RDONLY)
    monkeypatch.setenv(demo.LOCK_FD_ENV, str(fd))
    try:
        lab = FakeLab()
        rc, text = run_demo(lab)
    finally:
        os.close(fd)
    assert rc == 1
    assert text.startswith("Could not lock "), text
    assert lab.calls == []


def test_only_claude_local_settings_are_left_out() -> None:
    # The lab test ignores the file Claude Code rewrites on an approval, and
    # nothing else in .claude/.
    state = repo_state()
    assert ".claude/settings.json" in state
    assert ".claude/hooks/guard_delete.py" in state
    assert ".claude" not in state and ".claude/settings.local.json" not in state


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
    assert text.splitlines()[-2].startswith("Phase 2 checks: FAIL"), text


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


def run_live(argv: list[str], env: dict[str, str], lock: int) -> tuple[int, str]:
    """Start live mode, let it write two rounds, then press Ctrl+C (SIGINT)."""
    proc = subprocess.Popen(
        argv, cwd=ROOT, env=env, pass_fds=(lock,), stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True,
    )  # fmt: skip
    out = ""
    deadline = time.monotonic() + 300
    try:
        while out.count("live: wrote") < 2 and time.monotonic() < deadline:
            if select.select([proc.stdout], [], [], 5)[0]:
                line = proc.stdout.readline()
                if not line:
                    break
                out += line
        proc.send_signal(signal.SIGINT)
        rest, _ = proc.communicate(timeout=120)
    except BaseException:
        proc.kill()
        raise
    return proc.returncode, out + rest


@pytest.mark.lab
def test_demo_runs_change_nothing_but_their_own_files_in_lab_demo() -> None:
    lab_hosts.hosts("node")  # skips without inventory/lab.yml
    names = [
        name
        for group in yaml.safe_load(lab_hosts.INVENTORY.read_text())["all"]["children"].values()
        for name in (group or {}).get("hosts") or {}
    ]
    saved = str(REAL_SAVED.relative_to(ROOT))
    saved_dir = str(REAL_SAVED.parent.relative_to(ROOT))
    page = str(REAL_PAGE.relative_to(ROOT))
    # Hold the demo lock for every step and share it with each run, so
    # another demo run (make demo-html in a terminal) is refused instead of
    # writing .lab/demo/ under the test. That happened in the B2 runs.
    REAL_SAVED.parent.mkdir(exist_ok=True)
    lock = os.open(REAL_SAVED.parent, os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock)
        pytest.fail(f"another demo run is writing {saved_dir}; rerun the test when it ends")
    env = {**os.environ, demo.LOCK_FD_ENV: str(lock)}
    make_demo = ["make", "--no-print-directory", "demo"]
    python = str(ROOT / ".venv" / "bin" / "python")
    # The script make demo-live runs, with 1 s rounds; stopped by Ctrl+C.
    live = [python, "-B", "scripts/demo.py", "--html", "--live", "--interval", "1"]
    # The full run first: QUICK=1 and the pages show the result it saves.
    # The page runs are the script without --open, as make demo-html and make
    # demo-live would open a browser. The static page comes last, so the page
    # left behind does not reload itself.
    steps = (
        (make_demo, {saved}, {saved, saved_dir}, "saved for QUICK=1 in .lab/demo/phase2.json"),
        ([*make_demo, "QUICK=1"], set(), set(), "QUICK=1 did not rerun them"),
        (live, {page}, {page, saved_dir}, "live: stopped"),
        ([python, "-B", "scripts/demo.py", "--html"], {page}, {page, saved_dir},
         "Wrote .lab/demo/index.html"),
    )  # fmt: skip
    try:
        for argv, must_change, may_change, says in steps:
            repo_before = repo_state()
            vms_before = {name: vm_state(name) for name in names}
            if argv is live:
                code, out = run_live(argv, env, lock)
                assert out.count("live: wrote") >= 2 and "FAIL" not in out, out
                assert '<meta http-equiv="refresh" content="1">' in REAL_PAGE.read_text()
            else:
                result = subprocess.run(
                    argv, cwd=ROOT, env=env, pass_fds=(lock,), capture_output=True, text=True,
                    check=False, timeout=900,
                )  # fmt: skip
                code, out = result.returncode, result.stdout + result.stderr
                assert "Phase 2 checks: PASS" in out, out
            vms_after = {name: vm_state(name) for name in names}
            changed = changed_keys(repo_before, repo_state())
            assert code == 0, out
            assert says in out, out
            assert must_change <= changed <= may_change, (argv, sorted(changed))
            for name in names:
                gone = sorted(set(vms_before[name]) - set(vms_after[name]))
                new = sorted(set(vms_after[name]) - set(vms_before[name]))
                assert (gone, new) == ([], []), (argv, name)
    finally:
        os.close(lock)
