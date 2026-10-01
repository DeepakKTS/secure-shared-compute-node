# ADR 0003: Ansible roles for all configuration

Status: accepted

Context: The point is repeatability across several DASH machines and reviewability by someone else.

Decision: ansible-core with one role per concern, variables in group_vars, testinfra for effective state.

Alternatives: shell scripts (not idempotent, hard to review), Salt/Puppet (agent overhead for a small cluster), NixOS (too far from what DASH likely runs).

Consequences: Idempotency is enforced by `make idempotency`. Any `command`/`shell` task must be justified and guarded.
