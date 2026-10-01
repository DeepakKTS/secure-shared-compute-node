"""Recursive deletes must fail closed on an empty variable (docs/AUTONOMY.md).

`rm -rf "$d/"` with an empty d deletes from /. `set -u` stops an unset
variable, not an empty one; `${d:?}` stops both. So every variable in the
path of a recursive rm in this repo's code is written `${NAME:?}` (in a
Makefile recipe, `$${NAME:?}`). These need no VMs.
"""

import re
import shlex
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CODE_SUFFIXES = {".sh", ".py", ".yml", ".yaml", ".j2", ".tmpl", ".cfg"}
# rm with its flags, then the rest of that command (up to ; & | ' or the end).
RM = re.compile(r"(?<![\w.-])rm((?:\s+-\S+)+)\s+([^;&|'\n]*)")
GUARDED = re.compile(r"\$+\{\w+:\?")
# Files that hold delete commands only as sample text, never run.
SAMPLE_TEXT_FILES = {Path(__file__).name, "test_guard_delete.py"}


def recursive(flags: str) -> bool:
    return any(f == "--recursive" or (not f.startswith("--") and re.search(r"[rR]", f))
               for f in flags.split())  # fmt: skip


def unguarded(line: str) -> list[str]:
    """Recursive rm commands in `line` with a `$` that is not `${NAME:?`."""
    bad = []
    for match in RM.finditer(line):
        flags, path = match.groups()
        if recursive(flags) and any(
            not GUARDED.match(path, i) for i in range(len(path)) if path[i] == "$" and
            (i == 0 or path[i - 1] != "$")
        ):  # fmt: skip
            bad.append(match.group(0).strip())
    return bad


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        ('rm -rf "$d"', True),
        ("rm -rf $d/", True),
        ('rm -r "${d}"', True),
        ("rm -rf $(mktemp -d)", True),
        ('rm -fr "$X"', True),
        ('rm -Rf "$X"', True),
        ('rm --recursive "$X"', True),
        ("rm -rf $$d", True),
        ('rm -rf "${d:?}"', False),
        ('rm -rf "${LAB_DIR:?}/lynis"', False),
        ('rm -rf "$${d:?}"', False),
        ("rm -rf .lab/lynis/before", False),
        ('rm -f "$f"', False),
        ("rm -f $f", False),
    ],
)
def test_checker_flags_unguarded_recursive_rm(line: str, flagged: bool) -> None:
    assert bool(unguarded(line)) == flagged, line


def code_files() -> list[Path]:
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    files = [ROOT / name for name in tracked]
    return [
        f for f in files
        if f.is_file() and f.name not in SAMPLE_TEXT_FILES
        and (f.suffix in CODE_SUFFIXES or f.name == "Makefile")
    ]  # fmt: skip


def test_every_recursive_rm_guards_its_variables() -> None:
    bad = [
        f"{path.relative_to(ROOT)}:{number}: {cmd}"
        for path in code_files()
        for number, line in enumerate(path.read_text().splitlines(), 1)
        for cmd in unguarded(line)
    ]
    assert not bad, "recursive rm with an unguarded variable:\n" + "\n".join(bad)


def fail2ban_validate() -> list[str]:
    """The validate command of the fail2ban template task, as Ansible runs it
    for jail.d/ssc.local: `%s` filled in, split like a command line."""
    tasks = yaml.safe_load((ROOT / "roles/fail2ban/tasks/main.yml").read_text())
    (task,) = [t for t in tasks if "validate" in t.get("ansible.builtin.template", {})]
    command = task["ansible.builtin.template"]["validate"]
    return shlex.split(command.replace("{{ item.path }}", "jail.d/ssc.local"))


def stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


@pytest.mark.parametrize("mktemp_works", [False, True])
def test_fail2ban_validate_never_runs_rm_on_an_empty_path(
    tmp_path: Path, mktemp_works: bool
) -> None:
    # Stubs on PATH: rm only records its arguments, cp does nothing, and
    # mktemp either fails (d stays empty) or names a fresh directory.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    rm_log = tmp_path / "rm.log"
    scratch = tmp_path / "scratch"
    stub(bin_dir, "rm", f'printf "%s\\n" "$@" >> "{rm_log}"')
    stub(bin_dir, "cp", "exit 0")
    make_scratch = f'/bin/mkdir "{scratch}" && echo "{scratch}"'
    stub(bin_dir, "mktemp", make_scratch if mktemp_works else "exit 1")
    candidate = tmp_path / "ssc.local"
    candidate.write_text("[DEFAULT]\n")
    command = [arg.replace("%s", str(candidate)) for arg in fail2ban_validate()]

    result = subprocess.run(
        command, env={"PATH": str(bin_dir)}, capture_output=True, text=True, check=False
    )

    assert result.returncode != 0  # no fail2ban-client here, so never a pass
    calls = rm_log.read_text().split("\n") if rm_log.exists() else []
    if mktemp_works:
        # The scratch copy is still cleaned up, and only it.
        assert calls == ["-rf", str(scratch), ""], calls
    else:
        assert calls == [], calls
