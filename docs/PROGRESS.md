# Progress

One line per task: date, task ID, commit, what was verified. "built, not verified" means the box stays unticked.

- 2026-10-01 P0.1 b51ff14 `make help` matches the CLAUDE.md section 7 targets; later-phase stubs exit non-zero with their phase; `make lint`/`make test` refuse without `.venv/`; `make -n all` runs in order (GNU make 3.81)
- 2026-10-01 P0.2 c01b194 `make deps` installs pinned tools and collections; `make lint` passes (ansible-lint production profile); `make test` passes (policy tests: exact pins recorded in VERSIONS.md, secrets paths gitignored, force pushes denied); `uv lock --check` clean
- 2026-10-01 P0.3 67acbe2 built, not verified (needs Multipass for F-01). Unit tests with a fake multipass pass under bash 3.2: launch args and sizes, key and cloud-init content, idempotent up, disk refusal, down refuses without confirmation, down deletes only lab VMs, snapshot sequence; shellcheck clean; make lint and make test pass
- 2026-10-01 P0.4 e0981c0 built, not verified (needs VMs for F-02 and to check controller IP detection). Unit tests pass: fail-closed host selection, lab_cidr derivation and override, controller IP detection order, small profile groups, ssh_config; pinned ansible-inventory parses the generated file; make lint and make test pass
- 2026-10-01 P0.5 63b3651 built, not verified (needs Multipass for a real two-VM launch). README documents the small profile and its weakness; unit tests cover lab.sh and inventory small-profile behavior and LAB_PROFILE reaching make recipes; Makefile contract tests added; make lint and make test pass
- 2026-10-01 P0.6 651d446 (ticked in 6ca1b71) GitHub Actions run 36824227733 green: make deps, make lint (ansible-lint production profile), make test on ubuntu-24.04; actions pinned to commit SHAs
- 2026-10-01 P0.7 a3e807e built, not verified (Multipass and Ubuntu image rows pending until Multipass is installed). Every pinned Python package, collection and CI action is recorded with source and date; policy test enforces it
