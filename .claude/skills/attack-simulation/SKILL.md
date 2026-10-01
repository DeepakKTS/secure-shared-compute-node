---
name: attack-simulation
description: Safety rules and structure for writing attack simulation scenarios (S1 to S6) and the fake pool listener. Use for anything under simulate/ and scripts/measure.py.
---

# Attack simulation

## Safety first (hard rules)
- Scenarios are driven from the controller (the host running `make`). Every script sources `simulate/lib/guard.sh` and calls `guard_target <ip>` before any network action. Bash cannot parse YAML safely, so the guard calls a small Python check (PyYAML from `.venv/`) that reads `inventory/lab.yml`. It exits non-zero unless the IP is one of the lab hosts and inside `lab_cidr`. It fails closed if the inventory is missing or cannot be parsed. Any script copied to a VM receives only IPs the guard has already approved.
- No real miner software, no downloads from the internet. The "miner" is a small C CPU burn loop, compiled as a static binary on the attacker VM (the node stays free of compilers) and copied over. Do not use a Python loop for S3: `python3` is on the process allowlist, so it would hide, which is a real weakness to document, not to exploit in a test meant to show detection.
- The "mining pool" is a TCP listener on the attacker VM port 3333 that only logs connection attempts. It runs as a systemd unit that is only installed on hosts in the `attacker` group.
- Brute force uses a tiny fixed list of usernames that do not exist (or an account outside AllowGroups). Password login is disabled anyway. With key-only sshd, these are the log lines fail2ban's default mode counts; an existing allowed account without its key may not count. Confirm with `fail2ban-regex` on the VM. Limit attempts; the goal is to trigger fail2ban, not to crack anything.
- Every scenario has a cleanup step that runs even on failure (`trap cleanup EXIT`): kill payloads, remove crontab entries, unban the attacker IP.

## Structure
```
simulate/scenarios/S3/
  run.sh          # orchestrates: record start, run payload, wait, call measure.py, cleanup
  payload/        # source for harmless payload if needed
  expected.yml    # what must happen: prevented?, detections (source + rule), max wait seconds
```

## Timing
- Each run gets a unique `run_id`. Put it in payload paths and names (for example `~alice/.cache/<run_id>/`), so it shows up in Falco output and audit records.
- Before the run, check VM clock offsets (`chronyc tracking`) and record them in `env`. Fail the run if an offset is too large to trust the timing.
- Record `started_at` in UTC with milliseconds immediately before the triggering action.
- `measure.py` waits up to `max_wait_seconds`, reading `alerts.jsonl` on the monitor over SSH, and records the first alert per expected source that carries the run's `run_id` (Prometheus alerts, which have no run marker, match on rule, host, and group name after `started_at`). Missing detections are recorded as `null` with `passed: false`.
- Also collect local evidence: `fail2ban-client status sshd`, `nft list counters` or log lines, `ausearch -k <key>`.

## Expected outcomes summary
| ID | Prevented | Detected by |
|---|---|---|
| S1 | follow-up connection refused after ban | fail2ban |
| S2 | direct exec denied; interpreter case not prevented | auditd, Falco |
| S3 | no (runs from home) but capped by slice | Falco (seconds), Prometheus (minutes) |
| S4 | connection dropped | nftables log, Falco |
| S5 | no, but the relaunched payload is in a capped cgroup | Falco, auditd |
| S6 | usage capped | slice metrics, optional Prometheus |
