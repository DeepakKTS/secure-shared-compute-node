"""Makefile contract tests (CLAUDE.md section 7). They only run stub targets,
`help`, and a helper target from a temp makefile; never lab, deps, or ping."""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STUBS = {
    "idempotency": 2,
    "verify": 2,
    "monitoring": 4,
    "detection": 5,
    "simulate": 6,
    "audit": 7,
    "report": 7,
}


def make(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["make", "--no-print-directory", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_help_lists_every_target_in_claude_md() -> None:
    documented = set(re.findall(r"^\| `make ([a-z-]+)`", (ROOT / "CLAUDE.md").read_text(), re.M))
    listed = {line.split()[0] for line in make("help").stdout.splitlines() if line.strip()}
    assert documented, "no make targets found in CLAUDE.md section 7"
    assert documented <= listed, f"missing from Makefile: {sorted(documented - listed)}"
    assert listed - documented == {"help"}


@pytest.mark.parametrize(("target", "phase"), sorted(STUBS.items()))
def test_unbuilt_targets_fail_with_their_phase(target: str, phase: int) -> None:
    result = make(target)
    assert result.returncode != 0
    assert f"make {target}: not implemented yet (Phase {phase}" in result.stderr


def test_tool_targets_refuse_without_venv(tmp_path: Path) -> None:
    # Not `make test`: if the guard broke, pytest would call itself.
    for target in ("lint", "ping"):
        result = make(target, f"VENV={tmp_path / 'no-venv'}")
        assert result.returncode != 0
        assert "Run 'make deps' first." in result.stderr


@pytest.mark.parametrize(
    ("args", "env_value", "expected"),
    [((), None, "full"), (("LAB_PROFILE=small",), None, "small"), ((), "small", "small")],
)
def test_lab_profile_reaches_recipes(
    tmp_path: Path, args: tuple[str, ...], env_value: str | None, expected: str
) -> None:
    helper = tmp_path / "show.mk"
    helper.write_text('show-profile:\n\t@echo "LAB_PROFILE=$$LAB_PROFILE"\n')
    env = {"PATH": "/usr/bin:/bin"}
    if env_value:
        env["LAB_PROFILE"] = env_value
    result = make("-s", "-f", "Makefile", "-f", str(helper), "show-profile", *args, env=env)
    assert result.stdout.strip() == f"LAB_PROFILE={expected}", result.stderr


def test_lab_up_ends_with_the_multipass_exec_check() -> None:
    # -n prints the recipe without running it.
    steps = make("-n", "lab-up").stdout.splitlines()
    assert steps[-2:] == [
        ".venv/bin/ansible-playbook playbooks/lab_check.yml",
        "scripts/lab.sh check",
    ]


def test_baseline_audits_then_parses_a_fresh_report() -> None:
    steps = make("-n", "baseline").stdout.splitlines()
    assert steps[-3:] == [
        "rm -f .lab/lynis/before/ssc-node-lynis-report.dat",
        ".venv/bin/ansible-playbook playbooks/audit.yml -e audit_label=before",
        ".venv/bin/python scripts/parse_lynis.py .lab/lynis/before/ssc-node-lynis-report.dat"
        " --label before",
    ]


@pytest.mark.parametrize(
    ("args", "expected"),
    [((), ""), (("TAGS=base",), " --tags base"), (("TAGS=base,users",), " --tags base,users")],
)
def test_harden_runs_the_playbook_with_optional_tags(args: tuple[str, ...], expected: str) -> None:
    steps = make("-n", "harden", *args).stdout.splitlines()
    assert steps[-1].rstrip() == f".venv/bin/ansible-playbook playbooks/harden.yml{expected}"


@pytest.mark.parametrize(("args", "expected"), [((), ""), (("QUICK=1",), " --quick")])
def test_demo_runs_the_script_without_writing_bytecode(
    args: tuple[str, ...], expected: str
) -> None:
    steps = make("-n", "demo", *args).stdout.splitlines()
    assert steps[-1].rstrip() == f".venv/bin/python -B scripts/demo.py{expected}"


def test_demo_html_writes_the_page_then_opens_it() -> None:
    steps = make("-n", "demo-html").stdout.splitlines()
    assert steps[-1] == ".venv/bin/python -B scripts/demo.py --html --open"


def test_demo_live_rebuilds_the_page_until_stopped() -> None:
    steps = make("-n", "demo-live").stdout.splitlines()
    assert steps[-1] == ".venv/bin/python -B scripts/demo.py --html --live --open"


@pytest.mark.parametrize(
    ("args", "expected"), [((), ""), (("HOSTS=node",), " -e reboot_hosts=node")]
)
def test_reboot_runs_the_playbook_with_optional_hosts(args: tuple[str, ...], expected: str) -> None:
    steps = make("-n", "reboot", *args).stdout.splitlines()
    assert steps[-1].rstrip() == f".venv/bin/ansible-playbook playbooks/reboot.yml{expected}"
