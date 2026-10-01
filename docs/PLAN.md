# Build Plan

Phases run in order. Each phase ends with a working, committed state and a passing check. Do not start a phase until the previous phase's exit check passes.

Two milestones matter for the RA application:

- **Milestone A (shareable, target about 1 week):** Phases 0, 1, 2, 3, 4 (without Grafana and the GPU exporter), 5, 6 (S1 to S4), 7. This is enough to send Professor Chan a repo with real before/after numbers and working miner detection.
- **Milestone B (complete, v1.0):** everything else: Grafana (P4.6), GPU exporter (P4.7), S5 and S6, Phases 8 and 9, and the full `LAB_PROFILE=small` check (F-05).

Why Phases 3 and 4 are in Milestone A: Falco alerts reach `alerts.jsonl` only through falcosidekick, Alertmanager and alert_receiver (Phase 4). S3 expects a Prometheus alert (Phase 4 exporters plus P5.1 rules) and a CPU cap (Phase 3). Without them, S3 cannot pass.

If time is short, finish Milestone A properly rather than all phases partially.

---

## Phase 0: Bootstrap and lab tooling

**Goal:** one command creates the lab; lint runs; CI exists.

Work:
- `Makefile`, `ansible.cfg`, `requirements.yml`, `pyproject.toml`, `uv.lock`, `.python-version`, `.yamllint`, `.ansible-lint`, `.gitignore`.
- `ansible.cfg` points at `inventory/lab.yml`, not at the `inventory/` directory. Otherwise Ansible would try to parse `lab.yml.example` with the INI plugin.
- `scripts/lab.sh up|down|status|snapshot <name>` using Multipass. Generate an admin SSH key into `.lab/keys/` on first run. Pass the public key through cloud-init (`scripts/cloud-init.yaml.tmpl`), keeping the default `ubuntu` user that Multipass needs.
- `lab.sh down` deletes only the lab VMs by name (`multipass delete --purge <names>`). Never run a bare `multipass purge`, which affects every deleted instance on the machine.
- `scripts/gen_inventory.py`: reads `multipass list --format json`, writes `inventory/lab.yml` with groups `node`, `monitor`, `attacker`, plus `lab_cidr` and `lab_controller_ip`. This file is also the allowlist for simulation targets.
  - `multipass list` gives IPs but no netmask. `lab_cidr` is the network of the host bridge that Multipass created (bridge100 and up on macOS, `mpqemubr0` or `mpbr0` on Linux), narrowed to at most a /24 and inside the RFC 1918 ranges. A private address is not enough on its own, because a VM bridged onto a campus network also has one. Each VM's address is the one inside `lab_cidr`. A `LAB_CIDR` override may only narrow it.
  - `lab_controller_ip` is the source address the host uses to reach the VMs. The firewall and fail2ban always allow it.
  - SSH options in the inventory: absolute key path, `IdentitiesOnly=yes` (so a busy ssh-agent does not hit `MaxAuthTries`), and a project `known_hosts` in `.lab/` with `StrictHostKeyChecking=accept-new` (VMs get new host keys when recreated).
  - Also writes `.lab/ssh_config` so a person can run `ssh -F .lab/ssh_config ssc-node`.
- `playbooks/lab_check.yml`, run at the end of `make lab-up`: waits for connection, asserts Ubuntu 24.04, reports architecture and kernel, warns if `/sys/kernel/btf/vmlinux` is missing (Falco's modern eBPF driver needs it).
- Detect host OS, architecture and free disk in `lab.sh`; fail with a clear message if Multipass is missing.
- `.github/workflows/ci.yml`: yamllint, ansible-lint, `ansible-playbook --syntax-check`, shellcheck, ruff, pytest for pure-Python unit tests (inventory generation, guard logic, report rendering). CI runs the same `make` targets as a local run.

Exit check: `make deps && make lint && make test && make lab-up && make ping` succeeds. CI green once the repo is pushed.

## Phase 1: Baseline audit

**Goal:** capture how insecure a default server is, before any hardening.

Work:
- `playbooks/audit.yml` installs Lynis (pinned), runs `lynis audit system --quick --no-colors`, fetches `/var/log/lynis-report.dat` into `.lab/`.
- `scripts/parse_lynis.py` converts it to `results/lynis-<phase>.json` with hardening index, warning count, suggestion count, Lynis version, timestamp, host.

Exit check: `make baseline` writes `results/lynis-before.json` with a real hardening index.

## Phase 2: Host hardening

**Goal:** close the common entry points.

Before starting: `scripts/lab.sh snapshot pre-harden`. `multipass exec` rides on sshd, so the snapshot is the real rollback if SSH breaks.

Roles, in this order: `base`, `users`, `ssh_hardening`, `firewall`, `fail2ban`, `auto_updates`, `tmp_hardening`, `auditd`.

Where they run:
- `base` runs on all three VMs, so every clock comes from chrony.
- `users`, `ssh_hardening`, `firewall`, `fail2ban`, `auto_updates` run on the node and the monitor. The monitor gets its own firewall rules in Phase 4.
- `tmp_hardening` and `auditd` run on the node.

Key points (details in FEATURES.md and the skills):
- SSH: key-only, no root, AllowGroups, drop-in at `/etc/ssh/sshd_config.d/00-hardening.conf`, validated with `sshd -t`, checked with `sshd -T`. End with `meta: reset_connection` and a ping, so the check uses a new connection.
- nftables: default drop inbound; SSH from `firewall_admin_cidrs`, `lab_cidr` and always `lab_controller_ip`; exporter ports only from the monitor IP; egress set for stratum ports (filled in Phase 5).
- fail2ban: sshd jail, systemd backend, nftables banaction, `ignoreip` includes `lab_controller_ip` and the monitor.
- chrony in the lab steps the clock on any large offset (`makestep 1 -1`). After a laptop sleep, VM clocks can lag, and the Ubuntu default only steps at startup (verify in Phase 2).
- /tmp and /dev/shm mounted `noexec,nosuid,nodev`.
- auditd rules for exec from temp paths, cron/systemd/rc-file writes, sudoers changes, new SUID files. Per-user paths (`~/.config/systemd`, rc files) are rendered from `users_research`, because auditd does not expand `~` and a watch needs its parent directory to exist.

Exit check: `make harden && make idempotency && make verify` pass. You can still SSH in as admin with the key over a new connection. Password SSH fails. `multipass exec ssc-node -- true` still works.

## Phase 3: Multi-user isolation

**Goal:** no single user can take over the machine.

Work:
- `resource_limits` role: `/etc/systemd/system/user-.slice.d/50-ssc-limits.conf` with CPUQuota, MemoryMax, TasksMax from group_vars.
- Exempt the admin and `ubuntu` UIDs with per-UID drop-ins. sudo keeps Ansible's `become` tasks in the admin's slice, so a 768M cap would also cap apt runs.
- Cap `cron.service` and `atd.service` too. On Ubuntu, `pam_systemd` runs only for interactive sessions, so user cron and at jobs run in those services' cgroups, not in the user slice. Verify with `systemd-cgls` before relying on it.
- Research users have no sudo, home dirs 0700, umask 027.
- Optional (stretch): rootless Docker for research users. Behind `resource_limits_rootless_docker: false`.

Exit check: testinfra confirms limits are active for a logged-in research user (`systemctl show user-<uid>.slice`) and on `cron.service`. Scenario S6 later proves it.

## Phase 4: Monitoring

**Goal:** see per-host and per-process resource use from a separate box.

Work:
- On node: `node_exporter`, `process_exporter` (group name `<comm>:<user>`), `gpu_exporter` role present but disabled unless `gpu_enabled: true` (Milestone B).
- On monitor: `prometheus`, `alertmanager`, `alert_receiver`, and in Milestone B `grafana` (datasource and dashboards provisioned from `detection/grafana/`).
- `alert_receiver`: small Python HTTP service (systemd unit) that receives Alertmanager and falcosidekick webhooks and appends each alert with a receive timestamp to `/var/lib/ssc/alerts.jsonl`. This is the single source of truth for detection timing.
- Exporter ports on the node reachable only from monitor (nftables).
- Monitor firewall: Alertmanager and alert_receiver listen on localhost. The falcosidekick port accepts only the node. The Prometheus, Alertmanager and Grafana UIs accept only `lab_controller_ip`. This stops a rooted node from silencing alerts through the Alertmanager API.
- Alertmanager in the lab uses `group_by: ['...']` and a short `group_interval`, so each distinct alert is sent on its own and quickly.

Exit check: all targets are `up` via the Prometheus API (`make verify`). In Milestone B, Grafana also shows node CPU and per-process CPU.

## Phase 5: Detection

**Goal:** catch miner and intrusion behavior in seconds to minutes, through one alert pipeline.

Work:
- Prometheus rules (`detection/prometheus/rules/`): sustained high CPU by a non-allowlisted process group; host CPU saturated; node exporter down (possible tampering); unexpected new listening port (optional). The allowlist regex matches the `<comm>` part of the group name. Linux cuts comm to 15 characters, so allowlist entries use the cut form.
- Falco on node, modern eBPF driver, custom rules in `/etc/falco/rules.d/ssc.yaml`: exec from /tmp, /dev/shm, /var/tmp or hidden dirs in home; binary names matching known miner names; outbound connection to stratum ports; writes to crontabs, systemd unit dirs, shell rc files by non-admin users; process name masquerading (kernel-thread-like names from user processes). Output fields include the executable path and command line, so a scenario's run marker shows up in the alert.
- Falco `http_output` to falcosidekick on monitor; falcosidekick forwards to Alertmanager and to alert_receiver.
- nftables egress: named set `ssc_mining_ports`, action per `firewall_egress_mode` (`log_and_drop` default). Log prefix `SSC-EGRESS-BLOCK`.
- Alertmanager routes everything to `alert_receiver`. Optional email/Slack receiver behind a variable, off by default.

Exit check: manually trigger one Falco rule and one Prometheus alert; both appear in `alerts.jsonl` with labels identifying rule and host.

## Phase 6: Attack simulation

**Goal:** prove each control works, with timestamps.

Scenarios are driven from the controller (the host running `make`). The guard runs there, before any network action. Each run gets a unique run ID that appears in payload paths and names, and `measure.py` matches alerts on it, so an old alert from an earlier scenario cannot count. Before each run, `measure.py` checks VM clock offsets and records them.

Scenarios (full spec in FEATURES.md, F-60 to F-66):
- S1 SSH brute force from attacker: expect fail2ban ban and blocked follow-up connection. Attempts use usernames that do not exist, or an account outside AllowGroups. With key-only sshd, those are the log lines fail2ban's default mode counts. Confirm with `fail2ban-regex` on the VM.
- S2 Miner dropped in /tmp: expect direct exec prevented (noexec). Interpreter launch (`sh /tmp/x.sh`) is not stopped by noexec, so expect it to be detected by Falco and auditd instead.
- S3 Disguised miner run from a user's home (renamed to look like a kernel thread): expect Falco alert in seconds and Prometheus alert in minutes.
- S4 Outbound connection to fake pool on attacker port 3333: expect drop, nftables log, Falco alert.
- S5 (Milestone B) Persistence via user crontab: expect Falco and auditd records, and the relaunched payload still capped.
- S6 (Milestone B) One user tries to use all CPU and memory: expect cgroup caps hold; node stays responsive for others.

Each scenario: `simulate/scenarios/SX/run.sh` (sources guard), `expected.yml` (what must happen), and writes `results/scenarios/SX.json` via `scripts/measure.py`.

Exit check: `make simulate` passes every scenario in the current milestone, or reports which expectation failed. Failures are fixed, not hidden.

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
- ansible-lint `production` profile passes (it is the lint profile from Phase 0, so this should already hold).
- Run `security-reviewer` subagent over the whole repo; fix findings.
- Tag `v1.0.0`, write a short release note.

Exit check: CI green, tag pushed, README accurate.
