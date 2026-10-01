# Build Plan

Phases run in order. Each phase ends with a working, committed state and a passing check. Do not start a phase until the previous phase's exit check passes.

Two milestones matter for the RA application:

- **Milestone A (shareable, target about 1 week):** Phases 0, 1, 2, 5 (Falco + egress part), 6 (S1 to S4), 7. This is enough to send Professor Chan a repo with real before/after numbers and working miner detection.
- **Milestone B (complete, v1.0):** all phases.

If time is short, finish Milestone A properly rather than all phases partially.

---

## Phase 0: Bootstrap and lab tooling

**Goal:** one command creates the lab; lint runs; CI exists.

Work:
- `Makefile`, `ansible.cfg`, `requirements.yml`, `pyproject.toml`, `.gitignore`.
- `scripts/lab.sh up|down|status` using Multipass. Generate an admin SSH key into `.lab/keys/` on first run. Pass the public key through cloud-init.
- `scripts/gen_inventory.py`: reads `multipass list --format json`, writes `inventory/lab.yml` with groups `node`, `monitor`, `attacker`, plus `lab_cidr`. This file is also the allowlist for simulation targets.
- Detect host OS and architecture in `lab.sh`; fail with a clear message if Multipass is missing.
- `.github/workflows/ci.yml`: yamllint, ansible-lint, `ansible-playbook --syntax-check`, shellcheck, ruff, pytest for pure-Python unit tests (guard logic, report rendering).

Exit check: `make lab-up && make lint && ansible all -m ping` succeeds. CI green.

## Phase 1: Baseline audit

**Goal:** capture how insecure a default server is, before any hardening.

Work:
- `playbooks/audit.yml` installs Lynis (pinned), runs `lynis audit system --quick --no-colors`, fetches `/var/log/lynis-report.dat`.
- `scripts/parse_lynis.py` converts it to `results/lynis-<phase>.json` with hardening index, warning count, suggestion count, Lynis version, timestamp, host.

Exit check: `make baseline` writes `results/lynis-before.json` with a real hardening index.

## Phase 2: Host hardening

**Goal:** close the common entry points.

Roles, in this order: `base`, `users`, `ssh_hardening`, `firewall`, `fail2ban`, `auto_updates`, `tmp_hardening`, `auditd`.

Key points (details in FEATURES.md and the skills):
- SSH: key-only, no root, AllowGroups, drop-in at `/etc/ssh/sshd_config.d/00-hardening.conf`, validated with `sshd -t`, checked with `sshd -T`.
- nftables: default drop inbound; SSH only from `firewall_admin_cidrs`; exporter ports only from the monitor IP; egress set for stratum ports (filled in Phase 5).
- fail2ban: sshd jail, systemd backend, nftables banaction.
- /tmp and /dev/shm mounted `noexec,nosuid,nodev`.
- auditd rules for exec from temp paths, cron/systemd/rc-file writes, sudoers changes, new SUID files.

Exit check: `make harden && make idempotency && make verify` pass. You can still SSH in as admin with the key. Password SSH fails.

## Phase 3: Multi-user isolation

**Goal:** no single user can take over the machine.

Work:
- `resource_limits` role: `/etc/systemd/system/user-.slice.d/50-ssc-limits.conf` with CPUQuota, MemoryMax, TasksMax from group_vars. Admin exempt via a per-UID override if needed.
- Research users have no sudo, home dirs 0700, umask 027.
- Optional (stretch): rootless Docker for research users. Behind `resource_limits_rootless_docker: false`.

Exit check: testinfra confirms limits are active for a logged-in research user (`systemctl show user-<uid>.slice`). Scenario S6 later proves it.

## Phase 4: Monitoring

**Goal:** see per-host and per-process resource use from a separate box.

Work:
- On node: `node_exporter`, `process_exporter` (groups by process name and user), `gpu_exporter` role present but disabled unless `gpu_enabled: true`.
- On monitor: `prometheus`, `alertmanager`, `grafana` (datasource and dashboards provisioned from `detection/grafana/`), `alert_receiver`.
- `alert_receiver`: small Python HTTP service (systemd unit) that receives Alertmanager webhooks and appends each alert with a receive timestamp to `/var/lib/ssc/alerts.jsonl`. This is the single source of truth for detection timing.
- Exporter ports reachable only from monitor (nftables).

Exit check: Grafana shows node CPU and per-process CPU. `make verify` checks all targets are `up` via the Prometheus API.

## Phase 5: Detection

**Goal:** catch miner and intrusion behavior in seconds to minutes, through one alert pipeline.

Work:
- Prometheus rules (`detection/prometheus/rules/`): sustained high CPU by a non-allowlisted process group; host CPU saturated; node exporter down (possible tampering); unexpected new listening port (optional).
- Falco on node, modern eBPF driver, custom rules in `/etc/falco/rules.d/ssc.yaml`: exec from /tmp, /dev/shm, /var/tmp or hidden dirs in home; binary names matching known miner names; outbound connection to stratum ports; writes to crontabs, systemd unit dirs, shell rc files by non-admin users; process name masquerading (kernel-thread-like names from user processes).
- Falco `http_output` to falcosidekick on monitor; falcosidekick forwards to Alertmanager.
- nftables egress: named set `ssc_mining_ports`, action per `firewall_egress_mode` (`log_and_drop` default). Log prefix `SSC-EGRESS-BLOCK`.
- Alertmanager routes everything to `alert_receiver`. Optional email/Slack receiver behind a variable, off by default.

Exit check: manually trigger one Falco rule and one Prometheus alert; both appear in `alerts.jsonl` with labels identifying rule and host.

## Phase 6: Attack simulation

**Goal:** prove each control works, with timestamps.

Scenarios (full spec in FEATURES.md, F-60 to F-66):
- S1 SSH brute force from attacker: expect fail2ban ban and blocked follow-up connection.
- S2 Miner dropped in /tmp: expect direct exec prevented (noexec). Interpreter launch (`sh /tmp/x.sh`) is not stopped by noexec, so expect it to be detected by Falco and auditd instead.
- S3 Disguised miner run from a user's home (renamed to look like a kernel thread): expect Falco alert in seconds and Prometheus alert in minutes.
- S4 Outbound connection to fake pool on attacker port 3333: expect drop, nftables log, Falco alert.
- S5 Persistence via user crontab: expect Falco and auditd records.
- S6 One user tries to use all CPU and memory: expect cgroup caps hold; node stays responsive for others.

Each scenario: `simulate/scenarios/SX/run.sh` (sources guard), `expected.yml` (what must happen), and writes `results/scenarios/SX.json` via `scripts/measure.py`.

Exit check: `make simulate` passes all six, or reports which expectation failed. Failures are fixed, not hidden.

## Phase 7: Evidence and report

**Goal:** turn results into numbers anyone can trust.

Work:
- `make audit` writes `results/lynis-after.json`.
- `scripts/report.py` renders, between `<!-- SSC:RESULTS:START -->` and `<!-- SSC:RESULTS:END -->` in README.md: Lynis before/after, per-scenario outcome and time to detect, run date, git SHA, component versions.
- Keep the latest run in `results/` plus `results/history/` summaries.

Exit check: README numbers match JSON exactly; rerunning `make report` produces no diff.

## Phase 8: Documentation

Work:
- `docs/RUNBOOK.md`: miner incident response (detect, triage, contain, eradicate, recover, review), with exact commands.
- `docs/THREAT_MODEL.md` final: control-to-threat matrix filled with scenario evidence links.
- README: problem, architecture (Mermaid), quick start, results, limitations, "How this maps to DASH", questions for the DASH owner.
- Screenshots listed in `docs/SCREENSHOTS.md` (Grafana dashboard, alert firing). Take them by hand at the end.

Exit check: a reader can follow README quick start on a clean machine.

## Phase 9: Hardening the project itself

Work:
- ansible-lint `production` profile passes.
- Run `security-reviewer` subagent over the whole repo; fix findings.
- Tag `v1.0.0`, write a short release note.

Exit check: CI green, tag pushed, README accurate.
