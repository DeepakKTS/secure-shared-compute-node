# Progress

One line per task: date, task ID, commit, what was verified. "built, not verified" means the box stays unticked.

- 2026-10-01 P0.1 b51ff14 `make help` matches the CLAUDE.md section 7 targets; later-phase stubs exit non-zero with their phase; `make lint`/`make test` refuse without `.venv/`; `make -n all` runs in order (GNU make 3.81)
- 2026-10-01 P0.2 c01b194 `make deps` installs pinned tools and collections; `make lint` passes (ansible-lint production profile); `make test` passes (policy tests: exact pins recorded in VERSIONS.md, secrets paths gitignored, force pushes denied); `uv lock --check` clean
