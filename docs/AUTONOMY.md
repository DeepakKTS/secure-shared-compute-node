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

## Never

- push with failing checks;
- tick a box that is not verified;
- write a number that does not come from `results/`;
- force-push.
