#!/usr/bin/env python3
"""PreToolUse hook for the Bash tool: block deletes outside this repo's .lab/
and build output (docs/AUTONOMY.md, "Deleting files").

Claude Code sends the tool call as JSON on stdin. Exit 0 lets the command
run. Exit 2 blocks it, and stderr tells Claude why. The settings entry turns
any other exit (a crash, a missing interpreter) into exit 2 as well, so the
hook fails closed. Written for Python 3.9 and later, because it runs under
whatever python3 the host has, not the repo's .venv.

The hook never runs the command; it reads the text.
- Each delete word in the text (rm, unlink, and find's -delete) must be one
  the hook can check: the first word of a simple command (find for -delete).
  A delete word inside quotes (ssh host '...', bash -c '...'), after sudo or
  xargs, in a find -exec, or in a comment cannot be checked, so it blocks.
  VM cleanup goes through a fixed script or an Ansible task instead.
- Each target must be a plain path (no $, backquote, glob, ~, backslash or
  redirection) strictly inside .lab/ but not .lab/keys, or inside build
  output: .venv/, .pytest_cache/, .ruff_cache/, or a __pycache__/ in the repo.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from pathlib import Path

# A fixed root: the repo this file is in, never a variable from the caller.
ROOT = Path(os.path.realpath(Path(__file__).parent.parent.parent))
LAB = ROOT / ".lab"
KEYS = LAB / "keys"
BUILD = [ROOT / ".venv", ROOT / ".pytest_cache", ROOT / ".ruff_cache"]

DELETE_WORD = re.compile(r"(?<![\w.-])(?:rm|unlink)(?![\w.-])")
DELETE_FLAG = re.compile(r"(?<![\w-])-delete(?![\w-])")
# Text the hook cannot predict: expansions, escapes and line breaks.
UNPREDICTABLE_TEXT = set("$`\\\n")
UNPREDICTABLE_PATH = set("*?[]{}~")
PUNCTUATION = set("();<>|&")
CHANGES_DIR = {"cd", "pushd", "popd"}
FIND_UNSAFE = {"-L", "-H", "-follow", "-exec", "-execdir", "-ok", "-okdir"}


def tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def simple_commands(words: list[str]) -> list[list[str]]:
    """Split at ; && || | & ( ). Redirections stay in their command."""
    commands: list[list[str]] = [[]]
    for word in words:
        if word and set(word) <= PUNCTUATION and not set(word) & set("<>"):
            commands.append([])
        else:
            commands[-1].append(word)
    return [command for command in commands if command]


def inside(path: Path, parent: Path) -> bool:
    return path == parent or path.is_relative_to(parent)


def target_problem(target: str, cwd: str | None, changes_dir: bool) -> str | None:
    if not target or set(target) & UNPREDICTABLE_PATH:
        return f"cannot tell what {target!r} names"
    path = Path(target)
    if not path.is_absolute():
        if cwd is None or changes_dir:
            return f"relative path {target!r} with no fixed working directory"
        path = Path(cwd) / path
    if ".." in path.parts:
        return f"{target!r} uses '..'"
    real = Path(os.path.realpath(path))
    if inside(real, KEYS):
        return f"{target!r} is in .lab/keys (the lab's SSH keys)"
    if real != LAB and inside(real, LAB):
        return None
    if any(inside(real, build) for build in BUILD):
        return None
    if inside(real, ROOT) and "__pycache__" in real.relative_to(ROOT).parts:
        return None
    return f"{target!r} is outside .lab/ and build output"


def delete_problem(command: list[str], cwd: str | None, changes_dir: bool) -> str | None:
    """Why this delete command is blocked, or None if every target is allowed."""
    if any(word and set(word) <= PUNCTUATION for word in command):
        return "a redirection in a delete command"
    name = os.path.basename(command[0])
    if name == "find":
        if set(command) & FIND_UNSAFE:
            return "find with -L, -H, -follow or -exec next to -delete"
        targets = []
        for word in command[1:]:
            if word.startswith("-") or word in {"(", "!", ","}:
                break
            targets.append(word)
        targets = targets or ["."]
    else:
        args = command[1:]
        end = args.index("--") if "--" in args else len(args)
        targets = [word for word in args[:end] if not word.startswith("-")] + args[end + 1 :]
    if not targets:
        return "a delete with no target"
    for target in targets:
        problem = target_problem(target, cwd, changes_dir)
        if problem:
            return problem
    return None


def check(command: str, cwd: str | None) -> str | None:
    """None if the command may run, else the reason it is blocked."""
    words = len(DELETE_WORD.findall(command))
    flags = len(DELETE_FLAG.findall(command))
    if not words and not flags:
        return None
    if set(command) & UNPREDICTABLE_TEXT:
        return "a delete next to $, a backquote, a backslash or a line break"
    try:
        commands = simple_commands(tokens(command))
    except ValueError as err:
        return f"cannot parse the command ({err})"
    changes_dir = any(os.path.basename(c[0]) in CHANGES_DIR for c in commands)
    checked_words = checked_flags = 0
    for command_words in commands:
        name = os.path.basename(command_words[0])
        if name in {"rm", "unlink"}:
            checked_words += 1
        elif name == "find" and "-delete" in command_words:
            checked_flags += command_words.count("-delete")
        else:
            continue
        problem = delete_problem(command_words, cwd, changes_dir)
        if problem:
            return problem
    if (checked_words, checked_flags) != (words, flags):
        return (
            "a delete word where the hook cannot check it (inside quotes, after sudo, "
            "xargs, ssh or bash -c, in find -exec, or in a comment)"
        )
    return None


def main() -> int:
    try:
        data = json.load(sys.stdin)
        command = data["tool_input"]["command"]
        cwd = data.get("cwd")
        if not isinstance(command, str):
            raise TypeError("tool_input.command is not a string")
    except Exception as err:
        print(f"guard_delete: cannot read the hook input ({err}); blocking.", file=sys.stderr)
        return 2
    reason = check(command, cwd if isinstance(cwd, str) else None)
    if reason is None:
        return 0
    print(
        f"Blocked by .claude/hooks/guard_delete.py: {reason}. Deletes on this host are "
        "allowed only inside .lab/ (not .lab/keys) and build output. VM cleanup goes "
        "through a fixed script or an Ansible task (docs/AUTONOMY.md).",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:  # fail closed on any bug in this file
        print(f"guard_delete: internal error ({err!r}); blocking.", file=sys.stderr)
        sys.exit(2)
