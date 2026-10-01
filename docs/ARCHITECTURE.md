# Architecture

## Components and data flow

```mermaid
flowchart LR
  subgraph attacker[ssc-attacker]
    SIM[Simulation scenarios]
    POOL[Fake pool listener :3333]
  end
  subgraph node[ssc-node: protected server]
    SSH[sshd key-only]
    NFT[nftables ingress + egress]
    F2B[fail2ban]
    AUD[auditd]
    FAL[Falco modern eBPF]
    NE[node_exporter]
    PE[process-exporter]
    SL[user slice limits]
    USERS[research users]
  end
  subgraph monitor[ssc-monitor]
    PROM[Prometheus + rules]
    AM[Alertmanager]
    FSK[falcosidekick]
    RX[alert_receiver -> alerts.jsonl]
    GRAF[Grafana]
  end
  SIM -->|SSH brute force| SSH
  USERS -. miner-like payload .-> NFT
  NFT -. dropped .-> POOL
  F2B --> NFT
  FAL -->|http_output| FSK --> AM
  FSK --> RX
  NE --> PROM
  PE --> PROM
  PROM -->|alerts| AM --> RX
  PROM --> GRAF
```

## Defense layers

| Layer | Controls | Speed |
|---|---|---|
| Prevent entry | Key-only SSH, AllowGroups, nftables ingress, fail2ban, patching | immediate |
| Prevent execution | noexec on /tmp and /dev/shm | immediate |
| Prevent profit | Egress drop to stratum ports | immediate |
| Limit damage | Per-user CPU, memory, task caps; caps on the cron and at services | immediate |
| Detect fast | Falco runtime rules | seconds |
| Detect by behavior | Prometheus per-process CPU alerts | minutes (bounded by scrape interval + `for:`) |
| Record | auditd, journald, nftables logs | for investigation |
| Respond | Runbook | human |

The layers overlap on purpose. A miner that avoids /tmp still hits the CPU cap, the egress block, and the per-process alert. A miner that throttles itself to stay under the CPU threshold still needs a pool connection.

The CPU cap has a gap to close. User cron and at jobs run in the cgroups of `cron.service` and `atd.service`, not in the user's slice, because `pam_systemd` only runs for interactive sessions on Ubuntu. So those services get their own caps (ADR 0008; verify in Phase 3).

## Why the monitor is a separate VM

If monitoring runs on the node, anyone with root on the node can stop it and the silence looks like "all clear". A separate monitor turns that silence into an `SSCExporterDown` alert. On DASH this maps to a small admin VM or an existing campus monitoring host.

Separation only helps if the node cannot reach into the monitor. If the node could call the Alertmanager API, a root attacker could add a silence, and alerts would stop with no `SSCExporterDown` to show for it. So the monitor is hardened like the node. Alertmanager and alert_receiver listen on localhost. The falcosidekick port accepts only the node. The UIs accept only the admin host (`lab_controller_ip`).

## Detection timing

Alert receive time in `alerts.jsonl` is the single clock for "time to detect". All VMs sync time with chrony, and the lab config steps the clock on any large offset, because VM clocks can lag after the host laptop sleeps. `measure.py` checks clock offsets before each run and records them. It reports time to detect as `first_matching_alert.received_at - scenario.started_at`.

A matching alert must carry the scenario's `run_id`, which appears in payload paths and names. This stops an older alert from an earlier scenario from counting. falcosidekick sends Falco events to alert_receiver directly as well as to Alertmanager, because Alertmanager merges alerts with the same labels and could hold back a repeat event. In the lab, Alertmanager uses `group_by: ['...']` and a short `group_interval`.

Prometheus latency is roughly scrape interval + rule evaluation interval + the rule's `for:` duration + Alertmanager `group_wait`. Lab defaults are chosen for fast feedback. Production values for DASH should be longer to cut false positives, and that tradeoff is documented in `docs/adr/0006-alert-thresholds.md`.

## Configuration surface (what DASH would change)

All in `inventory/group_vars/`:
- `firewall_admin_cidrs`: who may SSH in (campus ranges or VPN). In the lab it stays empty, because `lab_cidr` and `lab_controller_ip` come from the generated inventory
- `users_research`: list of users and public keys
- `resource_limits_cpu_quota`, `resource_limits_memory_max`, `resource_limits_tasks_max`
- `detection_process_allowlist_regex`: expected heavy processes (python, jupyter, etc.), matched against the `<comm>` part of process-exporter's `<comm>:<user>` group name
- `detection_cpu_threshold`, `detection_cpu_for`
- `firewall_egress_mode`, `firewall_mining_ports`
- `gpu_enabled`
