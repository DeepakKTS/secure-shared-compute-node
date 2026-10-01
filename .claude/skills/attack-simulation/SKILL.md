---
name: attack-simulation
description: Safety rules and structure for writing attack simulation scenarios (S1 to S6) and the fake pool listener. Use for anything under simulate/ and scripts/measure.py.
---

# Attack simulation

## Safety first (hard rules)
- Every script sources `simulate/lib/guard.sh` and calls `guard_target <ip>` before any network action. The guard reads `inventory/lab.yml`, and exits non-zero unless the IP is one of the lab hosts and inside `lab_cidr`. It fails closed if the inventory is missing.
- No real miner software, no downloads from the internet. The "miner" is a small C CPU burn loop, compiled as a static binary on the attacker VM (the node stays free of compilers) and copied over. Do not use a Python loop for S3: `python3` is on the process allowlist, so it would hide, which is a real weakness to document, not to exploit in a test meant to show detection.
- The "mining pool" is a TCP listener on the attacker VM port 3333 that only logs connection attempts. It runs as a systemd unit that is only installed on hosts in the `attacker` group.
- Brute force uses a tiny fixed wordlist against a dedicated test account whose password login is disabled anyway. Limit attempts; the goal is to trigger fail2ban, not to crack anything.
- Every scenario has a cleanup step that runs even on failure (`trap cleanup EXIT`): kill payloads, remove crontab entries, unban the attacker IP.

## Structure
```
simulate/scenarios/S3/
  run.sh          # orchestrates: record start, run payload, wait, call measure.py, cleanup
  payload/        # source for harmless payload if needed
  expected.yml    # what must happen: prevented?, detections (source + rule), max wait seconds
```

## Timing
- Record `started_at` in UTC with milliseconds immediately before the triggering action.
- `measure.py` waits up to `max_wait_seconds`, reading `alerts.jsonl` on the monitor over SSH, and records the first matching alert per expected source. Missing detections are recorded as `null` with `passed: false`.
- Also collect local evidence: `fail2ban-client status sshd`, `nft list counters` or log lines, `ausearch -k <key>`.

## Expected outcomes summary
| ID | Prevented | Detected by |
|---|---|---|
| S1 | follow-up connection refused after ban | fail2ban |
| S2 | direct exec denied; interpreter case not prevented | auditd, Falco |
| S3 | no (runs from home) but capped by slice | Falco (seconds), Prometheus (minutes) |
| S4 | connection dropped | nftables log, Falco |
| S5 | no | Falco, auditd |
| S6 | usage capped | slice metrics, optional Prometheus |
