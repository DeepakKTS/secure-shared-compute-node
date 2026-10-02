#!/usr/bin/env python3
"""PreToolUse hook for the Bash tool: block deletes outside this repo's .lab/
and build output, and writes into the lab key directory or tracked files
(docs/AUTONOMY.md, "Deleting files").

Claude Code sends the tool call as JSON on stdin. Exit 0 lets the command
run. Exit 2 blocks it, and stderr tells Claude why. The settings entry turns
any other exit (a crash, a missing interpreter) into exit 2 as well, so the
hook fails closed. It runs under /usr/bin/python3 (3.9 on macOS, 3.12 on
Ubuntu 24.04), not the repo's .venv or whatever python3 is first on PATH, so
it is written for Python 3.9 and later.

The hook never runs the command; it reads the text.
- Delete commands: rm, unlink, shred, truncate, find with -delete, git clean
  (any flags), rsync with --delete, --del or --remove-source-files, and mv
  onto /dev/null. Each one in the text must be a plain command the hook can
  check: its first word, with no redirection. One inside quotes (ssh host
  '...', bash -c '...'), after sudo or xargs, in find -exec, or in a comment
  cannot be checked, so it blocks. VM cleanup goes through a fixed script or
  an Ansible task instead.
- Each target of a delete must be a plain path (no $, backquote, glob, ~,
  backslash or '..') strictly inside .lab/, or inside build output: .venv/,
  .pytest_cache/, .ruff_cache/, or a __pycache__/ in the repo. The lab keys
  live outside the repo (~/.config/ssc-lab/keys), so no allowed delete
  reaches them. mv onto /dev/null always blocks.
- Deletes written as code (os.remove, os.unlink, shutil.rmtree, .unlink(),
  rmtree, as in python3 -c or perl -e) always block: the hook cannot check
  their targets.
- A > redirect may not write into the lab key directory or a file git tracks
  in this repo (file changes go through the Edit and Write tools), or to a
  path the hook cannot predict. Redirects elsewhere outside the repo are
  allowed, so the key directory needs its own check.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import shlex
import subprocess
import sys
from pathlib import Path

# A fixed root: the repo this file is in, never a variable from the caller.
ROOT = Path(os.path.realpath(Path(__file__).parent.parent.parent))
LAB = ROOT / ".lab"
# KEY_DIR in scripts/lab.sh. The home directory comes from the account
# database, not $HOME, so the caller's environment cannot move it.
HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
KEYS = Path(os.path.realpath(HOME / ".config" / "ssc-lab" / "keys"))
BUILD = [ROOT / ".venv", ROOT / ".pytest_cache", ROOT / ".ruff_cache"]
DEV_NULL = "/dev/null"

# How often each kind of delete appears anywhere in the text. Every one must
# be matched by a plain command the hook checked.
B, A = r"(?<![\w.-])", r"(?![\w.-])"
TRIGGERS = {
    "rm, unlink, shred or truncate": re.compile(B + r"(?:rm|unlink|shred|truncate)" + A),
    "find -delete": re.compile(r"(?<![\w-])-delete(?![\w-])"),
    "git clean": re.compile(B + "git" + A + r"[^\n]*?" + B + "clean" + A),
    "rsync --delete": re.compile(
        B + "rsync" + A + r"[^\n]*?(?<![\w-])--(?:del|delete[\w-]*|remove-source-files)(?![\w-])"
    ),
}
MV_WORD = re.compile(B + "mv" + A)
CODE_DELETE = re.compile(
    r"os\.(?:remove|unlink|rmdir|removedirs)\b|shutil\.rmtree\b|\.(?:unlink|rmdir)\s*\("
    + "|"
    + B
    + "rmtree"
    + A
)

# Text the hook cannot predict: expansions, escapes and line breaks.
UNPREDICTABLE_TEXT = set("$`\\\n")
UNPREDICTABLE_PATH = set("$`*?[]{}~")
PUNCTUATION = set("();<>|&")
CHANGES_DIR = {"cd", "pushd", "popd"}
FIND_UNSAFE = {"-L", "-H", "-follow", "-exec", "-execdir", "-ok", "-okdir"}
SIMPLE_DELETES = {"rm", "unlink", "shred", "truncate"}
# Options whose value is the next word, so it is not read as a target.
VALUE_OPTIONS = {
    "shred": {"-n", "-s", "--iterations", "--size", "--random-source"},
    "truncate": {"-s", "-r", "--size", "--reference"},
    "git clean": {"-e", "--exclude"},
}


def tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def is_operator(word: str) -> bool:
    return bool(word) and set(word) <= PUNCTUATION


def simple_commands(words: list[str]) -> list[list[str]]:
    """Split at ; && || | & ( ). Redirections stay in their command."""
    commands: list[list[str]] = [[]]
    for word in words:
        if is_operator(word) and not set(word) & set("<>"):
            commands.append([])
        else:
            commands[-1].append(word)
    return [command for command in commands if command]


def split_redirects(words: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """The command's words without redirections, and the (operator, target) pairs."""
    args: list[str] = []
    redirects: list[tuple[str, str]] = []
    rest = iter(words)
    for word in rest:
        if is_operator(word):
            redirects.append((word, next(rest, "")))
        else:
            args.append(word)
    return args, redirects


def inside(path: Path, parent: Path) -> bool:
    return path == parent or path.is_relative_to(parent)


def resolve(target: str, cwd: str | None, changes_dir: bool) -> Path | str:
    """The real path a word names, or the reason it cannot be known."""
    if not target or set(target) & UNPREDICTABLE_PATH:
        return f"cannot tell what {target!r} names"
    path = Path(target)
    if not path.is_absolute():
        if cwd is None or changes_dir:
            return f"relative path {target!r} with no fixed working directory"
        path = Path(cwd) / path
    if ".." in path.parts:
        return f"{target!r} uses '..'"
    return Path(os.path.realpath(path))


def delete_target_problem(target: str, cwd: str | None, changes_dir: bool) -> str | None:
    real = resolve(target, cwd, changes_dir)
    if isinstance(real, str):
        return real
    if real != LAB and inside(real, LAB):
        return None
    if any(inside(real, build) for build in BUILD):
        return None
    if inside(real, ROOT) and "__pycache__" in real.relative_to(ROOT).parts:
        return None
    return f"{target!r} is outside .lab/ and build output"


_tracked: set[str] | None = None


def tracked_files() -> set[str]:
    global _tracked
    if _tracked is None:
        listing = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True, timeout=5
        )
        _tracked = set(listing.stdout.decode().split("\0")) - {""}
    return _tracked


def redirect_problem(op: str, target: str, cwd: str | None, changes_dir: bool) -> str | None:
    if ">" not in op:
        return None
    if op.endswith("&") and re.fullmatch(r"\d+|-", target):
        return None  # 2>&1 and the like duplicate a descriptor; no file
    real = resolve(target, cwd, changes_dir)
    if isinstance(real, str):
        return f"a {op} redirect: {real}"
    if inside(real, KEYS):
        return f"a {op} redirect into {KEYS} (the lab's SSH keys)"
    if inside(real, ROOT) and real.relative_to(ROOT).as_posix() in tracked_files():
        return f"a {op} redirect onto {target!r}, a file git tracks (use the Edit or Write tool)"
    return None


def positional(args: list[str], value_options: set[str]) -> list[str]:
    """Targets: words that are not options, and every word after --."""
    found: list[str] = []
    skip = False
    for index, word in enumerate(args):
        if skip:
            skip = False
        elif word == "--":
            return found + args[index + 1 :]
        elif word.startswith("-"):
            skip = word in value_options
        else:
            found.append(word)
    return found


def delete_kind(args: list[str]) -> tuple[str | None, int, list[str], str | None]:
    """(trigger, how many it accounts for, targets, problem) for one command."""
    name = os.path.basename(args[0])
    rest = args[1:]
    if name in SIMPLE_DELETES:
        targets = positional(rest, VALUE_OPTIONS.get(name, set()))
        return "rm, unlink, shred or truncate", 1, targets, None
    if name == "find" and "-delete" in rest:
        if set(rest) & FIND_UNSAFE:
            return "find -delete", 0, [], "find with -L, -H, -follow or -exec next to -delete"
        starts = []
        for word in rest:
            if word.startswith("-") or word in {"(", "!", ","}:
                break
            starts.append(word)
        return "find -delete", rest.count("-delete"), starts or ["."], None
    if name == "git" and rest[:1] == ["clean"]:
        return "git clean", 1, positional(rest[1:], VALUE_OPTIONS["git clean"]) or ["."], None
    if name == "rsync" and any(TRIGGERS["rsync --delete"].search("rsync " + w) for w in rest):
        paths = positional(rest, set())
        if len(paths) < 2:
            return "rsync --delete", 1, [], "rsync with a delete option and no clear destination"
        if any(":" in path for path in paths):
            return "rsync --delete", 1, [], "rsync with a delete option to or from another host"
        removes_sources = "--remove-source-files" in rest
        return "rsync --delete", 1, paths if removes_sources else paths[-1:], None
    return None, 0, [], None


def check(command: str, cwd: str | None) -> str | None:
    """None if the command may run, else the reason it is blocked."""
    if CODE_DELETE.search(command):
        return (
            "a delete written as code (os.remove, os.unlink, shutil.rmtree, .unlink(), rmtree): "
            "the hook cannot check its targets"
        )
    expected = {kind: len(pattern.findall(command)) for kind, pattern in TRIGGERS.items()}
    mv_words = len(MV_WORD.findall(command)) if DEV_NULL in command else 0
    deleting = any(expected.values()) or mv_words
    if not deleting and ">" not in command:
        return None
    if deleting and set(command) & UNPREDICTABLE_TEXT:
        return "a delete next to $, a backquote, a backslash or a line break"
    try:
        commands = simple_commands(tokens(command))
    except ValueError as err:
        return f"cannot parse the command ({err})"
    changes_dir = any(os.path.basename(c[0]) in CHANGES_DIR for c in commands)
    checked = dict.fromkeys(expected, 0)
    checked_mv = 0
    for words in commands:
        args, redirects = split_redirects(words)
        for op, target in redirects:
            problem = redirect_problem(op, target, cwd, changes_dir)
            if problem:
                return problem
        if not args:
            continue
        if os.path.basename(args[0]) == "mv" and mv_words:
            checked_mv += 1
            if any(w == DEV_NULL or w.endswith("=" + DEV_NULL) for w in args[1:]):
                return "mv onto /dev/null"
            continue
        kind, count, targets, problem = delete_kind(args)
        if kind is None:
            continue
        checked[kind] += count
        if problem:
            return problem
        if redirects:
            return "a redirection in a delete command"
        if not targets:
            return "a delete with no target"
        for target in targets:
            problem = delete_target_problem(target, cwd, changes_dir)
            if problem:
                return problem
    for kind, count in expected.items():
        if checked[kind] != count:
            return (
                f"{kind} where the hook cannot check it (inside quotes, after sudo, xargs, "
                "ssh or bash -c, with options before the subcommand, or in a comment)"
            )
    if checked_mv != mv_words:
        return "mv near /dev/null where the hook cannot check it"
    return None


def log_block(reason: str, command: object, cwd: object) -> None:
    """Record the block in .lab/audit/bash.log (bash_log.py). A logging failure
    never lets the command through; it is only reported."""
    try:
        import bash_log

        bash_log.append({"event": "blocked", "reason": reason, "command": command, "cwd": cwd})
    except Exception as err:
        print(f"guard_delete: could not log the block ({err!r})", file=sys.stderr)


def main() -> int:
    try:
        data = json.load(sys.stdin)
        command = data["tool_input"]["command"]
        cwd = data.get("cwd")
        if not isinstance(command, str):
            raise TypeError("tool_input.command is not a string")
    except Exception as err:
        print(f"guard_delete: cannot read the hook input ({err}); blocking.", file=sys.stderr)
        log_block(f"cannot read the hook input ({err})", None, None)
        return 2
    reason = check(command, cwd if isinstance(cwd, str) else None)
    if reason is None:
        return 0
    log_block(reason, command, cwd)
    print(
        f"Blocked by .claude/hooks/guard_delete.py: {reason}. Deletes on this host are "
        "allowed only inside .lab/ and build output, and tracked files "
        "change only through the Edit and Write tools. VM cleanup goes through a fixed "
        "script or an Ansible task (docs/AUTONOMY.md).",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:  # fail closed on any bug in this file
        print(f"guard_delete: internal error ({err!r}); blocking.", file=sys.stderr)
        sys.exit(2)
