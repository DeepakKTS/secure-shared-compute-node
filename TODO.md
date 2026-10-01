# TODO

Work top to bottom. Check a box only when its feature's acceptance check in `docs/FEATURES.md` passes. Put the verification command in the commit body.

Current phase: **0**

## Phase 0: Bootstrap
- [ ] P0.1 Makefile skeleton with all targets from CLAUDE.md section 7 (stubs allowed)
- [ ] P0.2 ansible.cfg, requirements.yml (pinned collections), pyproject.toml (pinned dev deps), .gitignore
- [ ] P0.3 scripts/lab.sh up/down/status with host OS check and admin key generation (F-01, F-03)
- [ ] P0.4 scripts/gen_inventory.py (F-02)
- [ ] P0.5 LAB_PROFILE=small support (F-05)
- [ ] P0.6 CI workflow (F-04)
- [ ] P0.7 docs/VERSIONS.md started
- [ ] Exit: `make lab-up && make lint && ansible all -m ping`

## Phase 1: Baseline
- [ ] P1.1 playbooks/audit.yml with pinned Lynis (F-10)
- [ ] P1.2 scripts/parse_lynis.py + unit test (F-11)
- [ ] Exit: `make baseline` writes results/lynis-before.json

## Phase 2: Hardening
- [ ] P2.1 role base (F-20)
- [ ] P2.2 role users (F-21)
- [ ] P2.3 role ssh_hardening (F-22)
- [ ] P2.4 role firewall, ingress only for now (F-23)
- [ ] P2.5 role fail2ban (F-24)
- [ ] P2.6 role auto_updates (F-25)
- [ ] P2.7 role tmp_hardening (F-26)
- [ ] P2.8 role auditd (F-27)
- [ ] P2.9 make idempotency (F-28)
- [ ] P2.10 testinfra tests for every role above
- [ ] Exit: `make harden && make idempotency && make verify`, admin key login works, password login fails

## Phase 3: Isolation
- [ ] P3.1 role resource_limits (F-30)
- [ ] P3.2 umask and home permissions (F-31)
- [ ] P3.3 (stretch) rootless Docker (F-32)
- [ ] Exit: testinfra confirms slice limits

## Phase 4: Monitoring
- [ ] P4.1 role node_exporter (F-40)
- [ ] P4.2 role process_exporter (F-41)
- [ ] P4.3 role prometheus (F-42)
- [ ] P4.4 role alert_receiver (F-45)
- [ ] P4.5 role alertmanager (F-43)
- [ ] P4.6 role grafana + dashboard JSON (F-44)
- [ ] P4.7 role gpu_exporter, disabled by default (F-46)
- [ ] P4.8 firewall: exporter ports from monitor only
- [ ] Exit: all targets up, dashboard shows data

## Phase 5: Detection
- [ ] P5.1 Prometheus alert rules + promtool in CI (F-50, F-51)
- [ ] P5.2 role falco (F-52)
- [ ] P5.3 Falco custom rules (F-53 to F-56)
- [ ] P5.4 role falcosidekick (F-57)
- [ ] P5.5 firewall egress mining ports (F-58)
- [ ] Exit: one Falco event and one Prometheus alert in alerts.jsonl

## Phase 6: Simulation
- [ ] P6.1 simulate/lib/guard.sh + unit tests (F-60)
- [ ] P6.2 fake pool listener on attacker (systemd unit, lab only)
- [ ] P6.3 scripts/measure.py + fixtures (F-70)
- [ ] P6.4 S1 (F-61)
- [ ] P6.5 S2 (F-62)
- [ ] P6.6 S3 (F-63)
- [ ] P6.7 S4 (F-64)
- [ ] P6.8 S5 (F-65)
- [ ] P6.9 S6 (F-66)
- [ ] Exit: `make simulate` all pass

## Phase 7: Evidence
- [ ] P7.1 make audit -> results/lynis-after.json
- [ ] P7.2 scripts/report.py + README markers (F-71, F-72)
- [ ] Exit: README matches JSON; rerun produces no diff

## Phase 8: Docs
- [ ] P8.1 docs/RUNBOOK.md (F-80)
- [ ] P8.2 docs/THREAT_MODEL.md evidence links (F-81)
- [ ] P8.3 README final (F-82)
- [ ] P8.4 screenshots (manual)

## Phase 9: Release
- [ ] P9.1 ansible-lint production profile
- [ ] P9.2 security-reviewer pass, findings fixed
- [ ] P9.3 tag v1.0.0

## Parking lot (not in scope unless promoted)
- DNS blocklist for mining pool domains (needs local resolver; adds a moving part)
- Central log shipping (Loki or similar)
- SLURM job scheduler integration
- Default-deny egress with allowlist (too strict for research downloads without DASH user input)
