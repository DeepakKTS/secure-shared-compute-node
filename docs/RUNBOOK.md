# Runbook: Suspected Crypto Miner or Malware

Status: outline. Fill in exact commands during Phase 8, and test each one against scenario S3 and S5 output.

## 1. Detect
- Alert sources and what each means (Falco rule, SSCUnknownProcessHighCPU, egress block log, fail2ban ban)
- Where to look first: Grafana dashboard, `alerts.jsonl`, `journalctl -u falco`

## 2. Triage (is it real?)
- Identify process, user, parent, start time, binary path, network connections
- Compare against the allowlist and the user's expected work
- Decide: false positive (tune), misuse (policy), or compromise (security incident)

## 3. Contain
- Stop the process without destroying evidence (SIGSTOP first, then collect)
- Lock the user account and kill sessions
- Keep egress block in place; confirm no other host shows the same pattern

## 4. Collect evidence
- Copy binary and hash it, process tree, open files, network connections, relevant audit records by key, auth logs

## 5. Eradicate
- Remove persistence: user and system crontabs, systemd user units, rc files, authorized_keys changes
- Rotate the affected user's keys

## 6. Recover
- Patch, rerun `make harden` to restore known-good config, rerun `make verify`
- Unlock the user only after key rotation and a conversation

## 7. Review
- How did it get in, which layer caught it, how long it took, what to change
- Notify the DASH owner and, if required, university IT security
