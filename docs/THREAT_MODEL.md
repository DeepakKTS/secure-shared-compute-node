# Threat Model

## Assets
- Compute capacity (CPU, GPU, memory) of the shared server
- Research users' data and home directories
- Integrity of the server's OS and configuration
- Trust in monitoring (alerts reflect reality)
- The university network's reputation (outbound abuse from its IPs)

## Actors
- **A1 External attacker** on the internet or campus network, no account
- **A2 Attacker with a stolen user credential**, normal user privileges
- **A3 Insider user**, legitimate account, misuses resources on purpose or by accident

## Threats

| ID | Threat | Actor | Controls | Evidence |
|---|---|---|---|---|
| T1 | Initial access via SSH brute force or unpatched service | A1 | F-22 SSH hardening, F-23 ingress firewall, F-24 fail2ban, F-25 patching | S1 |
| T2 | Code execution from writable temp paths after access | A1, A2 | F-26 noexec, F-27 auditd, F-53 Falco | S2 |
| T3 | Resource abuse by a user account | A2, A3 | F-30 slice limits and cron/at service caps, F-50 alert | S6 |
| T4 | Crypto miner running disguised | A1, A2, A3 | F-50, F-53, F-55 | S3 |
| T5 | Miner reaching a mining pool | A1, A2, A3 | F-58 egress drop, F-54 Falco | S4 |
| T6 | Monitoring tampering or silencing | A1 with root | separate, hardened monitor (F-29), Alertmanager on localhost, F-51 ExporterDown | manual test |
| T7 | Persistence (cron, systemd user units, rc files) | A1, A2 | F-27 auditd, F-56 Falco, runbook | S5 |
| T8 | Privilege escalation to root | A2, A3 | no sudo for users, patching, sysctl, auditd SUID watch | partial; see limitations |

## Limitations (state these honestly in the README)
- A miner that throttles CPU below the threshold and tunnels pool traffic over HTTPS/443 evades the metric alert and port-based egress block. Falco exec/path rules and the CPU cap still apply. Full coverage would need DNS or TLS-SNI filtering, which is in the parking lot.
- A kernel-level rootkit after root compromise can hide from Falco and exporters on that host. The separate monitor detects exporter loss, not a lying exporter.
- The lab uses CPU-only VMs. GPU mining detection is designed (DCGM exporter role) but not demonstrated.
- Thresholds were tuned on a quiet lab. Real research workloads (training jobs) will need allowlist and threshold tuning with the DASH owner.
- The CPU alert allowlist matches on process name. A miner launched as `python3` or renamed to an allowlisted name would not trigger it. Matching on name plus user plus executable path is stronger and should be considered for DASH; Falco path rules and egress blocking still apply.
- User cron and at jobs run outside the user slice. The project caps `cron.service` and `atd.service` as a whole, so all users' cron jobs share one cap instead of each user getting their own (verify in Phase 3).
- In the lab, the admin and `ubuntu` accounts are exempt from slice limits, so Ansible and Multipass recovery keep working. A stolen admin key is not limited by the caps.
- This is not a CIS benchmark certification. Lynis index is an indicator, not a guarantee.
