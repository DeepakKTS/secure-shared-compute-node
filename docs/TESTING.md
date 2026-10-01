# Testing Strategy

| Level | Tool | Runs where | What it proves |
|---|---|---|---|
| Static | yamllint, ansible-lint, shellcheck, ruff, `promtool check rules`, `falco --validate` (if available in CI, else on node) | CI + local | Files are valid and follow conventions |
| Syntax | `ansible-playbook --syntax-check` | CI | Playbooks parse |
| Unit | pytest | CI | guard logic, Lynis parser, measure.py, report.py using fixtures |
| Idempotency | `make idempotency` | local lab | Configuration converges, no drift |
| State | pytest-testinfra over SSH | local lab | Settings are actually live on the host (sshd -T, nft ruleset, mounts, sysctl, services, slices) |
| Behavior | `make simulate` | local lab | Controls stop or detect real attack behavior |

## Rules
- Every role gets a `tests/test_<role>.py`.
- Test the effective state, not the file. Example: check `sshd -T` output, not the contents of the drop-in.
- Full integration cannot run in GitHub Actions (needs VMs with eBPF and systemd). Say so in the README instead of faking it.
- Fixtures for measure.py and report.py live in `tests/fixtures/` and include a case where no alert arrives (must report "not detected", not crash).
