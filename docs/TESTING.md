# Testing Strategy

| Level | Tool | Runs where | What it proves |
|---|---|---|---|
| Static | yamllint, ansible-lint, shellcheck, ruff, `promtool check rules`, `falco --validate` (if available in CI, else on node) | CI + local | Files are valid and follow conventions |
| Syntax | `ansible-playbook --syntax-check` | CI | Playbooks parse |
| Unit | pytest | CI | inventory generator, guard logic, Lynis parser, measure.py, report.py using fixtures |
| Idempotency | `make idempotency` | local lab | Configuration converges, no drift |
| State | pytest-testinfra over SSH | local lab | Settings are actually live on the host (sshd -T, nft ruleset, mounts, sysctl, services, slices) |
| Boot | `make reboot`, then testinfra again | local lab | Settings survive a reboot. A unit that runs later in boot can undo them (apport reset `fs.suid_dumpable`; a vendor `sysctl.d` file reset `fs.protected_fifos`). A standard step for every role that sets boot-time state |
| Behavior | `make simulate` | local lab | Controls stop or detect real attack behavior |

## Rules
- Every role gets a `tests/test_<role>.py`.
- Tests that need the lab VMs are marked `lab`. `make test` runs everything else, locally and in CI.
- Run tools from `.venv/` (`make deps`), not from the system PATH, so local and CI versions match.
- Test the effective state, not the file. Example: check `sshd -T` output, not the contents of the drop-in.
- Prove a test can fail. Before applying a control, run its tests against the unprotected host and see them fail (the firewall tests did: closed ports were refused, a new listener was reachable).
- Lab test modules get hosts from `tests/lab_hosts.py` with plain group names (`hosts("node", "monitor")`). testinfra does not understand Ansible patterns such as `node:monitor`: one matched no host, every test was skipped, and pytest exited 0. An unknown or empty group now fails, and so does any empty parameter set.
- testinfra's SSH backend treats exit code 255 as "could not reach the test host" and raises. A command whose own failure is 255 (an inner `ssh` that is refused) must print its exit code instead (`...; echo inner_rc=$?`).
- Full integration cannot run in GitHub Actions (needs VMs with eBPF and systemd). Say so in the README instead of faking it.
- Fixtures for measure.py and report.py live in `tests/fixtures/` and include a case where no alert arrives (must report "not detected", not crash), and a stale alert from an earlier run that must not match.
