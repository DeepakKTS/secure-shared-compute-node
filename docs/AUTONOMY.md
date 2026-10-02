# Autonomous loop rules

The owner runs Claude Code in a loop over `TODO.md`. These are the rules for that loop. They add to CLAUDE.md; they do not replace it. CLAUDE.md section 3 still wins over everything here.

## Each cycle

One TODO task per cycle.

1. Implement the task.
2. Verify it:
   - the task's own check from `docs/FEATURES.md`;
   - `make lint` and `make test`;
   - for roles, also the touched role's lab suite (`pytest -m lab tests/test_<role>.py`) and idempotency (a rerun reports `changed=0`);
   - `make reboot` and a recheck of the live values, only for roles that set boot-time state (sysctl, mounts, units, the firewall table, audit rules). Boot-time units have undone settings before, so for those roles a check that passed only before a reboot does not count.
3. Tick the box in `TODO.md`.
4. Commit, with the verification commands and their results in the commit body.
5. Push. Do not wait for CI; the phase end checks it.
6. Add one line to `docs/PROGRESS.md`.

## Phase end

1. Run all lab suites.
2. Reboot all VMs once (`make reboot`), then run all lab suites again.
3. Run `/verify-phase`.
4. Run the `security-reviewer` subagent.
5. Fix the must-fix items.
6. Confirm CI passed for every commit in the phase (`gh run list`). A red run is a failing check.
7. Update the status line in `README.md`.

## Pre-approved

These need no stop. Record each one in `docs/PROGRESS.md`.

- Moving a scenario-based part of an acceptance check to its Phase 6 task, as was done for F-24, F-26 and F-27. Say so in `docs/FEATURES.md` and `TODO.md`.
- Fixing a bug found on the way, as long as a test covers the fix.

## Snapshots

Take a Multipass snapshot (`scripts/lab.sh snapshot pre-<task>`) before every task that changes sshd, nftables, PAM, sudoers, or fail2ban. A mistake in any of these can lock out SSH, and the snapshot is the real rollback.

## Session length

Both stray deletes happened late in very long sessions. So a session does at most 5 TODO tasks. Then it writes the HANDOFF and stops, and the owner starts a fresh session. It stops earlier if the context is past half full. The owner can check that with `/context`. Claude cannot run that command itself, so it judges from the session's length and says so when it stops. Work that is not a TODO task (a fix the owner asks for, a review) counts toward the length, not toward the 5.

## Stop and wait for the owner when

- a check fails twice;
- something needs the owner: an install, a sudo password, a GitHub setting, or a must-fix item that cannot be resolved;
- an action is on the ask list in `.claude/settings.json`;
- a change would touch a rule in CLAUDE.md section 3, in any direction;
- anything targets an IP outside `inventory/lab.yml`;
- auto mode's safety check blocks a call;
- the session has finished 5 TODO tasks, or the context is past half full, whichever comes first (see "Session length"). Write the HANDOFF section at the top of `docs/PROGRESS.md` first.

## Deleting files

- No recursive delete on the host (the machine that runs `make`) outside this repo's own generated paths: `.lab/` and build output (`.venv/`, `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`). Run a delete as its own command, not chained after other commands, so the ask rule in `.claude/settings.json` sees it.
- Cleanup inside scripts, Makefile recipes and Ansible commands uses paths built from a fixed root: the repo root the script finds from its own location (`ROOT` in `scripts/lab.sh`), or a directory the same command just made with `mktemp -d`. Never a bare variable. Write every variable in a recursive delete as `${NAME:?}` (`$${NAME:?}` in a Makefile recipe), so an empty value stops the command. `set -u` alone is not enough: it stops an unset variable, not an empty one. `tests/test_safe_delete.py` checks this.
- Never chain a delete with other commands (`a && rm ...`, `a; rm ...`). Run it alone, so the command the owner reviews is the delete itself. Claude Code checks every part of a chain against the ask list, but a delete in the middle of a long line is easy to miss when reading it.
- A PreToolUse hook (`.claude/hooks/guard_delete.py`, registered in `.claude/settings.json`) enforces this on every Bash call. It blocks `rm`, `unlink`, `shred`, `truncate`, find's `-delete`, `git clean` (any flags; `-x` would reach `.lab/`), `rsync` with a delete option, and `mv` onto `/dev/null`, unless each one is a plain command whose targets are all inside `.lab/` (not `.lab` itself) or build output. The lab SSH keys live outside the repo, in `~/.config/ssc-lab/keys/`, so no allowed delete reaches them, and a symlink under `.lab/` is checked as the path it points to. Deletes written as code (`os.remove`, `os.unlink`, `shutil.rmtree`, `.unlink()`, `rmtree`, as in `python3 -c` or `perl -e`) always block. A `>` redirect into the key directory or onto a file git tracks blocks too; tracked files change through the Edit and Write tools. A delete word it cannot check (in quotes, after `sudo` or `xargs`, through `ssh` or `bash -c`, in a comment) blocks too, so cleanup on a VM goes through a fixed script or an Ansible task, never an ad-hoc `ssh ... rm`. It fails closed: if the hook itself errors, the command is blocked. Mentioning the word in a `git commit -m` message also blocks; write the message to a file and use `git commit -F`. `tests/test_guard_delete.py` covers it.
- Every Bash call is logged to `.lab/audit/bash.log` (gitignored): the command, its exit code and a UTC timestamp, from a PostToolUse and PostToolUseFailure hook (`.claude/hooks/log_bash.py`), plus one line for each call the guard blocked. `make audit-log` shows today's blocked attempts; `ALL=1` also lists what ran, `DATE=YYYY-MM-DD` picks another day. The owner reviews it after unattended work.
- The ask list matches the command text as written. It catches `rm -rf x`, `rm -r x`, `rm -fr x`, `rm -R x`, `/bin/rm ...` and `find ... -delete`, not `rm -Rf x`, `/usr/bin/rm` or `bash -c '...'`. It guards against mistakes; this rule is what covers the rest.

## Bash calls

Both stray deletes were extra pieces added to a call that was doing something else. These rules make that harder to do and easier to spot.

- One purpose per Bash call. No trailing cleanup after other commands; cleanup is its own call, or part of a fixed script.
- Read-only `grep` and `git grep` in Bash are fine when the command text names no delete word. The delete guard reads every Bash command's text, so a search for a delete word (as in a review of the hook itself) is blocked. For those, use the built-in Grep tool if the session has one, or read the file with the Read tool. The guard sees neither.
- Do not hide errors with `2>/dev/null` unless the command needs it, and then say why in the call's description. A hidden error is how a mistake goes unnoticed.
- Any temp work on a VM goes through a fixed script in the repo that runs on the VM. It makes its temp directory with `mktemp -d` and removes it with a `trap` on exit, on the VM side. No ad-hoc temp files over `ssh`, and no cleanup typed by hand afterwards.

## Scratch experiments

- A scratch experiment never points at a live config file. Copy the file first and point the experiment at the copy, or run it on a VM right after a snapshot. Tools can change their input: Ansible's `copy` with `validate` sets `mode` on its source, which once changed the live fail2ban jail file (see docs/PROGRESS.md, P2.5 incident).

## Never

- push with failing local checks (lint, unit tests, the task's lab checks);
- tick a box that is not verified;
- write a number that does not come from `results/`;
- force-push.
