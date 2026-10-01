# TODO

Work top to bottom. Check a box only when its feature's acceptance check in `docs/FEATURES.md` passes. Put the verification command in the commit body.

Current phase: **1**

Milestone A = every item not marked (Milestone B). See `docs/PLAN.md`.

## Phase 0: Bootstrap
- [x] P0.1 Makefile skeleton with all targets from CLAUDE.md section 7 (stubs exit non-zero)
- [x] P0.2 ansible.cfg, requirements.yml (pinned collections), pyproject.toml + uv.lock + .python-version (pinned dev deps), .yamllint, .ansible-lint, .gitignore
- [x] P0.3 scripts/lab.sh up/down/status/snapshot with host OS, arch and disk check, admin key generation, cloud-init template (F-01, F-03)
- [x] P0.4 scripts/gen_inventory.py with lab_cidr, lab_controller_ip, .lab/ssh_config, unit tests (F-02)
- [x] P0.5 LAB_PROFILE=small basic support in lab.sh and inventory (F-05, Milestone A part)
- [x] P0.6 CI workflow (F-04)
- [x] P0.7 docs/VERSIONS.md filled for Phase 0 tools
- [x] P0.8 playbooks/lab_check.yml (OS, arch, kernel, BTF), run by `make lab-up`
- [x] Exit: `make deps && make lint && make test && make lab-up && make ping`

## Phase 1: Baseline
- [x] P1.1 playbooks/audit.yml with pinned Lynis (F-10)
- [ ] P1.2 scripts/parse_lynis.py + unit test (F-11)
- [ ] Exit: `make baseline` writes results/lynis-before.json

## Phase 2: Hardening
- [x] P2.0 `scripts/lab.sh snapshot pre-harden`
- [ ] P2.1 role base, all hosts (F-20)
- [ ] P2.2 role users (F-21)
- [ ] P2.3 role ssh_hardening (F-22)
- [ ] P2.4 role firewall, ingress only for now (F-23)
- [ ] P2.5 role fail2ban (F-24)
- [ ] P2.6 role auto_updates (F-25)
- [ ] P2.7 role tmp_hardening (F-26)
- [ ] P2.8 role auditd (F-27)
- [ ] P2.9 make idempotency (F-28)
- [ ] P2.10 monitor gets base, users, ssh_hardening, firewall, fail2ban (F-29, monitor-specific ports in P4.8)
- [ ] P2.11 testinfra tests for every role above
- [ ] Exit: `make harden && make idempotency && make verify`, admin key login works over a new connection, password login fails, `multipass exec ssc-node -- true` works

## Phase 3: Isolation
- [ ] P3.1 role resource_limits: user slices, admin and ubuntu exempt, cron.service and atd.service capped (F-30)
- [ ] P3.2 umask and home permissions (F-31)
- [ ] P3.3 (stretch, Milestone B) rootless Docker (F-32)
- [ ] Exit: testinfra confirms slice and cron.service limits

## Phase 4: Monitoring
- [ ] P4.1 role node_exporter (F-40)
- [ ] P4.2 role process_exporter, group name `<comm>:<user>` (F-41)
- [ ] P4.3 role prometheus (F-42)
- [ ] P4.4 role alert_receiver (F-45)
- [ ] P4.5 role alertmanager (F-43)
- [ ] P4.6 (Milestone B) role grafana + dashboard JSON (F-44)
- [ ] P4.7 (Milestone B) role gpu_exporter, disabled by default (F-46)
- [ ] P4.8 firewall: exporter ports from monitor only; monitor ports per F-29
- [ ] P4.9 node_exporter textfile metric for pending reboot (F-47)
- [ ] Exit: all targets up (Milestone B: dashboard shows data)

## Phase 5: Detection
- [ ] P5.0 Allowlist matches name and user together (`<comm>:<user>`), so system names such as `systemd*`, `sshd` and `falco*` are exempt only for their own service users. A miner named `systemd-worker` run by alice must still alert; promtool test for `systemd-x:alice` (security review item 7)
- [ ] P5.1 Prometheus alert rules + promtool in CI (F-50, F-51)
- [ ] P5.2 role falco (F-52)
- [ ] P5.3 Falco custom rules (F-53 to F-56)
- [ ] P5.4 role falcosidekick (F-57)
- [ ] P5.5 firewall egress mining ports (F-58)
- [ ] P5.6 disk usage alert, with journald size limits (F-59; gap from the system guide)
- [ ] P5.7 reboot-pending alert (F-5A)
- [ ] Exit: one Falco event and one Prometheus alert in alerts.jsonl

## Phase 6: Simulation
- [ ] P6.1 simulate/lib/guard.sh + unit tests, runs on the controller (F-60)
- [ ] P6.2 fake pool listener on attacker (systemd unit, lab only)
- [ ] P6.3 scripts/measure.py + fixtures, run_id matching, clock offset check (F-70)
- [ ] P6.4 S1 (F-61)
- [ ] P6.5 S2 (F-62)
- [ ] P6.6 S3 (F-63)
- [ ] P6.7 S4 (F-64)
- [ ] P6.8 (Milestone B) S5 (F-65)
- [ ] P6.9 (Milestone B) S6 (F-66)
- [ ] Exit: `make simulate` passes S1 to S4 (Milestone B: all six)

## Phase 7: Evidence
- [ ] P7.1 make audit -> results/lynis-after.json
- [ ] P7.2 scripts/report.py + README markers (F-71, F-72)
- [ ] Exit: README matches JSON; rerun produces no diff

## Phase 8: Docs (Milestone B)
- [ ] P8.1 docs/RUNBOOK.md (F-80)
- [ ] P8.2 docs/THREAT_MODEL.md evidence links (F-81)
- [ ] P8.3 README final (F-82)
- [ ] P8.4 screenshots (manual)

## Phase 9: Release (Milestone B)
- [ ] P9.1 ansible-lint production profile
- [ ] P9.2 security-reviewer pass, findings fixed
- [ ] P9.3 tag v1.0.0
- [ ] P9.4 `make all` works with `LAB_PROFILE=small` (F-05, Milestone B part)

## Parking lot (not in scope unless promoted)
- DNS blocklist for mining pool domains (needs local resolver; adds a moving part)
- Central log shipping (Loki or similar)
- SLURM job scheduler integration
- Default-deny egress with allowlist (too strict for research downloads without DASH user input)
