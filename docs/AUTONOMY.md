# Autonomous loop rules

The owner runs Claude Code in a loop over `TODO.md`. These are the rules for that loop. They add to CLAUDE.md; they do not replace it. CLAUDE.md section 3 still wins over everything here.

## Each cycle

One TODO task per cycle.

1. Implement the task.
2. Verify it:
   - the task's own check from `docs/FEATURES.md`;
   - `make lint` and `make test`;
   - for roles, also idempotency (a rerun reports `changed=0`), testinfra against the lab, and `make reboot` followed by a recheck of the live values. Boot-time units have undone settings before, so a check that passed only before a reboot does not count.
3. Tick the box in `TODO.md`.
4. Commit, with the verification commands and their results in the commit body.
5. Push.
6. Add one line to `docs/PROGRESS.md`.

## Phase end

1. Run `/verify-phase`.
2. Run the `security-reviewer` subagent.
3. Fix the must-fix items.
4. Update the status line in `README.md`.

## Snapshots

Take a Multipass snapshot (`scripts/lab.sh snapshot pre-<task>`) before every task that changes sshd, nftables, PAM, sudoers, or fail2ban. A mistake in any of these can lock out SSH, and the snapshot is the real rollback.

## Stop and wait for the owner when

- something needs the owner: an install, a sudo password, or a GitHub setting;
- a check fails twice;
- a must-fix item cannot be resolved;
- a change would weaken a rule in CLAUDE.md section 3;
- an action is on the ask list in `.claude/settings.json`;
- anything targets an IP outside `inventory/lab.yml`;
- the context gets long. Write the HANDOFF section at the top of `docs/PROGRESS.md` first.

## Deleting files

- No recursive delete on the host (the machine that runs `make`) outside this repo's own generated paths: `.lab/` and build output (`.venv/`, `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`). Run a delete as its own command, not chained after other commands, so the ask rule in `.claude/settings.json` sees it.
- Cleanup inside scripts, Makefile recipes and Ansible commands uses paths built from a fixed root: the repo root the script finds from its own location (`ROOT` in `scripts/lab.sh`), or a directory the same command just made with `mktemp -d`. Never a bare variable. Write every variable in a recursive delete as `${NAME:?}` (`$${NAME:?}` in a Makefile recipe), so an empty value stops the command. `set -u` alone is not enough: it stops an unset variable, not an empty one. `tests/test_safe_delete.py` checks this.
- Never chain a delete with other commands (`a && rm ...`, `a; rm ...`). Run it alone, so the command the owner reviews is the delete itself. Claude Code checks every part of a chain against the ask list, but a delete in the middle of a long line is easy to miss when reading it.
- A PreToolUse hook (`.claude/hooks/guard_delete.py`, registered in `.claude/settings.json`) enforces this on every Bash call. It blocks any command with `rm`, `unlink` or find's `-delete` unless each one is a plain command whose targets are all inside `.lab/` (not `.lab` itself or `.lab/keys`) or build output. A delete word it cannot check (in quotes, after `sudo` or `xargs`, through `ssh` or `bash -c`, in a comment) blocks too, so cleanup on a VM goes through a fixed script or an Ansible task, never an ad-hoc `ssh ... rm`. It fails closed: if the hook itself errors, the command is blocked. Mentioning the word in a `git commit -m` message also blocks; write the message to a file and use `git commit -F`. `tests/test_guard_delete.py` covers it.
- The ask list matches the command text as written. It catches `rm -rf x`, `rm -r x`, `rm -fr x`, `rm -R x`, `/bin/rm ...` and `find ... -delete`, not `rm -Rf x`, `/usr/bin/rm` or `bash -c '...'`. It guards against mistakes; this rule is what covers the rest.

## Scratch experiments

- A scratch experiment never points at a live config file. Copy the file first and point the experiment at the copy, or run it on a VM right after a snapshot. Tools can change their input: Ansible's `copy` with `validate` sets `mode` on its source, which once changed the live fail2ban jail file (see docs/PROGRESS.md, P2.5 incident).

## Never

- push with failing checks;
- tick a box that is not verified;
- write a number that does not come from `results/`;
- force-push.
