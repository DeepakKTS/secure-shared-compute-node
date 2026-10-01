"""Makefile contract tests (CLAUDE.md section 7). They only run stub targets,
`help`, and a helper target from a temp makefile; never lab, deps, or ping."""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STUBS = {
    "baseline": 1,
    "harden": 2,
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
