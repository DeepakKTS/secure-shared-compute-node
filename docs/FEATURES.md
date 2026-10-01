# Features and Acceptance Criteria

Each feature has an ID, the threat it addresses, and how it is proven. A TODO item is done only when its acceptance check passes. T-IDs refer to `docs/THREAT_MODEL.md`.

## Lab and tooling (F-0x)

| ID | Feature | Acceptance check |
|---|---|---|
| F-01 | `make lab-up` creates node, monitor, attacker VMs on Multipass with admin key via cloud-init, keeps the `ubuntu` user for Multipass, writes `.lab/ssh_config`, runs `lab_check.yml` | `multipass list` shows 3 running; `ansible all -m ping` succeeds; `ssh -F .lab/ssh_config ssc-node true` succeeds |
| F-02 | Generated inventory with groups, `lab_cidr` and `lab_controller_ip` | `inventory/lab.yml` exists, gitignored, contains 3 hosts; unit tests cover the generator |
| F-03 | `make lab-down` with a typed confirmation read from `/dev/tty`, deleting only the lab VMs by name | refuses without a terminal, refuses any answer but `yes`, ignores `CONFIRM=yes` |
| F-04 | CI: yamllint, ansible-lint, syntax-check, shellcheck, ruff, pytest (unit) | GitHub Actions green |
| F-05 | `LAB_PROFILE=small` two-VM mode | Milestone A: documented; `lab.sh` and the inventory support it. Milestone B: `make all` works with it |

## Audit (F-1x)

| ID | Feature | Acceptance check |
|---|---|---|
| F-10 | Lynis install (pinned) and run via Ansible | report fetched to `.lab/` |
| F-11 | Lynis parser to JSON | `results/lynis-before.json` has `hardening_index`, `warnings`, `suggestions`, `lynis_version`, `timestamp` |

## Hardening (F-2x)

| ID | Feature | Threat | Acceptance check |
|---|---|---|---|
| F-20 | `base` on all VMs: apt cache, needed packages, chrony (lab `makestep 1 -1`), `NEEDRESTART_MODE=a`, sysctl hardening (e.g. `kernel.kptr_restrict`, `net.ipv4.conf.all.rp_filter`, `fs.suid_dumpable=0`) | T1, T2 | testinfra checks each sysctl value and that chrony is synced |
| F-21 | `users`: admin in sudo; research users from group_vars, no sudo, home 0700, group `ssc-users` | T2, T3 | testinfra: `sudo -l -U alice` shows no rights |
| F-22 | `ssh_hardening` on node and monitor: `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitRootLogin no`, `PubkeyAuthentication yes`, `AllowGroups sudo ssc-users`, `MaxAuthTries 3`, `LoginGraceTime 30`, `X11Forwarding no`, `AllowAgentForwarding no`, `ClientAliveInterval 300` | T1 | `sshd -T` shows each value; password login attempt from attacker fails; a new admin connection and `multipass exec` still work |
| F-23 | `firewall`: nftables, ufw disabled, default drop input, allow established, SSH from `firewall_admin_cidrs`, `lab_cidr` and `lab_controller_ip`, exporter ports only from monitor | T1 | `nft list ruleset` matches template; port scan from attacker shows only 22 |
| F-24 | `fail2ban`: sshd jail, `backend = systemd`, `banaction = nftables-multiport`, `ignoreip` includes `lab_controller_ip` and monitor, values from group_vars | T1 | `fail2ban-regex` matches the S1 log lines; testinfra rehearses S1 (attacker banned, next connection refused, ban kept across a firewall reload). The S1 scenario itself is checked in P6.4 |
| F-25 | `auto_updates`: unattended-upgrades for security origin, auto-reboot off (admin decides), mail optional | T1 | `apt-config dump` shows periodic settings |
| F-26 | `tmp_hardening`: /tmp and /dev/shm `noexec,nosuid,nodev` | T1, T2 | `findmnt /tmp` options, also after a reboot; testinfra: a user cannot run a binary from either path. The S2 scenario itself is checked in P6.5 |
| F-27 | `auditd`: rules for execve in temp paths, writes to `/etc/cron*`, `/var/spool/cron`, `/etc/systemd/system`, each research user's `~/.config/systemd` and shell rc files (rendered per user from `users_research`), `/etc/sudoers*`, SUID changes | T1, T2, T3 | `auditctl -l` lists rules; S2 and S5 find records by key |
| F-28 | Idempotency | all | second `make harden` shows `changed=0` |
| F-29 | Monitor hardening: base, users, ssh_hardening, firewall, fail2ban on the monitor; Alertmanager and alert_receiver on localhost; falcosidekick port from node only; UIs from `lab_controller_ip` only | T6 | port scan from node shows only 22 and the falcosidekick port; from attacker only 22; Alertmanager API unreachable from node |

## Isolation (F-3x)

| ID | Feature | Threat | Acceptance check |
|---|---|---|---|
| F-30 | Per-user systemd slice limits: `CPUQuota`, `MemoryMax`, `TasksMax` from group_vars; admin and `ubuntu` UIDs exempt; `cron.service` and `atd.service` capped, since user cron and at jobs run there | T3, T2 | `systemctl show user-<uid>.slice` and `systemctl show cron.service` show values; S6 passes |
| F-31 | umask 027 and private homes for research users | T3 | testinfra |
| F-32 | (stretch) rootless Docker per user | T3 | `docker info` as alice shows rootless |

## Monitoring (F-4x)

| ID | Feature | Acceptance check |
|---|---|---|
| F-40 | node_exporter on node, reachable only from monitor | Prometheus target up; curl from attacker times out |
| F-41 | process-exporter with group name `<comm>:<user>` | `namedprocess_namegroup_cpu_seconds_total` present per group |
| F-42 | Prometheus with scrape configs and rule files from `detection/` | `promtool check rules` passes in CI; targets up |
| F-43 | Alertmanager routing to `alert_receiver`; lab `group_by: ['...']` and short `group_interval` | test alert lands in `alerts.jsonl` |
| F-44 | Grafana provisioned datasource and dashboard (host, per-process, per-user, alerts) | dashboard loads with data |
| F-45 | `alert_receiver` systemd service appending JSONL with receive timestamp | unit active; unit tests for parsing |
| F-46 | GPU exporter role (DCGM), `gpu_enabled: false` default | role skips cleanly when disabled; documented |
| F-47 | node_exporter textfile collector exposes a pending-reboot metric (set when `/var/run/reboot-required` exists), so a patched kernel that is not running yet is visible | metric present at the node's `/metrics`; flips when the file is created and removed by hand |

## Detection (F-5x)

| ID | Feature | Threat | Acceptance check |
|---|---|---|---|
| F-50 | Prometheus alert `SSCUnknownProcessHighCPU`: per process group CPU rate above threshold for a set duration, excluding groups whose `<comm>` part matches the allowlist regex | T4 | `promtool test rules`: fires for an unknown name, not for `python3:alice`; S3 fires it |
| F-51 | Prometheus alerts `SSCHostCPUSaturated`, `SSCExporterDown` | T4, T6 | trigger by test; stopping node_exporter fires ExporterDown |
| F-52 | Falco installed with modern eBPF driver, version pinned | T4 | `systemctl status falco*` active; test event appears |
| F-53 | Falco rule: exec from temp or hidden paths | T4 | S3 or manual test |
| F-54 | Falco rule: outbound connect to stratum ports | T5 | S4 |
| F-55 | Falco rule: known miner process names and kernel-thread masquerading | T4 | S3 |
| F-56 | Falco rule: persistence writes (crontab, systemd user units, rc files) | T7 | S5 |
| F-57 | falcosidekick forwarding to Alertmanager and alert_receiver | T4 | Falco events reach `alerts.jsonl`, including a second identical event within a few seconds |
| F-58 | nftables egress set for mining ports, `log_and_drop` default, `log_only` option | T5 | S4 shows drop counter increment and log line |
| F-59 | Prometheus alert `SSCDiskSpaceLow` (free space on a filesystem below a group_vars threshold) and journald size limits (`SystemMaxUse`, `RuntimeMaxUse` from group_vars) in `base`. A full disk stops logging and auditd, which hides an attack | T6 | `promtool test rules` fires for low free space, not for normal; `systemd-analyze cat-config systemd/journald.conf` shows the limits |
| F-5A | Prometheus alert `SSCRebootPending` from the F-47 metric, held for a group_vars duration. Patches to the kernel and core libraries only protect after a reboot | T1 | `promtool test rules` fires when the metric is set past the duration |

## Simulation (F-6x)

Scenarios are driven from the controller. Every scenario sources `simulate/lib/guard.sh`, gets a unique `run_id` that appears in payload paths and names, records `started_at` in UTC with millisecond precision, and writes `results/scenarios/SX.json` with `expected`, `observed`, `passed`, and timing fields. Milestone A covers S1 to S4; S5 and S6 are Milestone B.

| ID | Scenario | Expected result |
|---|---|---|
| F-60 | Guard: refuses any target not in `inventory/lab.yml` | unit test with a public IP fails closed |
| F-61 | S1 SSH brute force (small fixed list of usernames that do not exist, or an account outside AllowGroups; key-only sshd logs no `Failed password` lines) | ban within configured `maxretry`; next connection refused; time to ban recorded |
| F-62 | S2 copy a harmless compiled binary to /tmp and run it directly (`./payload`); then run a script there through an interpreter (`sh /tmp/x.sh`) | direct exec denied by noexec; interpreter case is not prevented (expected) but is recorded by auditd and alerted by Falco |
| F-63 | S3 run a CPU-burning process from `~alice/.cache/`, renamed to a kernel-thread-like name | Falco alert (seconds) and `SSCUnknownProcessHighCPU` (minutes); both times recorded |
| F-64 | S4 connect from node to `attacker:3333` fake pool listener | connection fails; nftables log; Falco alert; listener receives nothing |
| F-65 | S5 add a user crontab entry that relaunches S3 payload | Falco and auditd records; the relaunched payload is in a capped cgroup; runbook step removes it |
| F-66 | S6 alice runs CPU and memory hogs | usage stays at cap; admin SSH latency stays under the threshold set in `expected.yml`; OOM kill confined to alice's slice |

## Evidence and docs (F-7x, F-8x)

| ID | Feature | Acceptance check |
|---|---|---|
| F-70 | `scripts/measure.py`: match scenario start to the first alert in `alerts.jsonl` that carries the scenario's `run_id`; check and record VM clock offsets | unit tests with fixture files, including a stale alert from an earlier run that must not match |
| F-71 | `scripts/report.py`: render README results block | idempotent; no diff on rerun |
| F-72 | Run metadata: git SHA, date, component versions | present in report |
| F-80 | Runbook | covers full miner incident with commands |
| F-81 | Threat model final | every threat maps to controls and evidence |
| F-82 | README with Mermaid architecture and DASH mapping | renders on GitHub |
