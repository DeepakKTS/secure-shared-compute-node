# Pinned Versions

Fill this in during the build. Check each against the upstream release page or apt repository on the day you pin it. Do not copy versions from memory.

| Component | Version | Source checked | Date checked |
|---|---|---|---|
| Ubuntu Server | 24.04 LTS; exact image build pending (recorded from `multipass info` when the lab is first created) | | |
| Multipass | pending (not installed on the build host yet) | | |
| Python (controller) | 3.12.13 (`.python-version`), the uv-managed build locally and in CI (`python-preference = "only-managed"`). It is the newest 3.12 that uv 0.11.29 can install; upstream has 3.12.15, which needs a newer uv | python/cpython tags on GitHub; `uv python list --all-platforms`; ansible-core 2.21.4 requires Python >= 3.12 on PyPI | 2026-10-01 |
| uv | 0.11.29 (`required-version` in pyproject.toml; `version` input of setup-uv in CI). Upstream latest is 0.12.21 | GitHub releases API (astral-sh/uv), release 0.11.29 published 2026-07-15 | 2026-10-01 |
| actions/checkout (CI) | v7.0.1, pinned to commit 3d3c42e5aac5ba805825da76410c181273ba90b1 | GitHub releases API | 2026-10-01 |
| astral-sh/setup-uv (CI) | v10.2.0, pinned to commit c18668ad3cf93ea998bef934396af7bb5c839dc7; installs uv 0.11.29 | GitHub releases API | 2026-10-01 |
| ansible-core | 2.21.4 | PyPI JSON API (pypi.org/pypi/<name>/json) | 2026-10-01 |
| community.general | 13.4.0 (requires ansible-core >= 2.18.0) | Galaxy API v3 (galaxy.ansible.com) | 2026-10-01 |
| ansible.posix | 2.2.2 (requires ansible-core >= 2.16.0) | Galaxy API v3 (galaxy.ansible.com) | 2026-10-01 |
| community.library_inventory_filtering_v1 | 1.1.5 (dependency of community.general, which asks for >=1.0.0) | Galaxy API v3 (galaxy.ansible.com) | 2026-10-01 |
| Lynis | | | |
| Prometheus | | | |
| Alertmanager | | | |
| node_exporter | | | |
| process-exporter | | | |
| Grafana | | | |
| Falco | | | |
| falcosidekick | | | |
| DCGM exporter (optional) | | | |
| ansible-lint | 26.9.0 | PyPI JSON API (pypi.org/pypi/<name>/json) | 2026-10-01 |
| yamllint | 1.38.0 | PyPI JSON API (pypi.org/pypi/<name>/json) | 2026-10-01 |
| ruff | 0.16.9 | PyPI JSON API (pypi.org/pypi/<name>/json) | 2026-10-01 |
| shellcheck (shellcheck-py) | 0.11.0.1 | PyPI JSON API (pypi.org/pypi/<name>/json) | 2026-10-01 |
| pytest | 9.1.1 | PyPI JSON API (pypi.org/pypi/<name>/json) | 2026-10-01 |
| pytest-testinfra | 10.2.2 | PyPI JSON API (pypi.org/pypi/<name>/json) | 2026-10-01 |
| PyYAML | 6.0.3 | PyPI JSON API (pypi.org/pypi/<name>/json) | 2026-10-01 |
