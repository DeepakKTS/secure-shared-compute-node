# From Lab to DASH

What carries over, what changes, and what to ask the DASH owner before touching real machines.

## Carries over as is
- All Ansible roles, applied to a DASH inventory instead of the lab inventory
- Detection rules, dashboards, runbook

## Changes
- `firewall_admin_cidrs` set to campus or VPN ranges
- Real user list and keys
- Resource caps sized to real hardware and workloads
- Allowlist tuned to real research software
- GPU exporter enabled if machines have NVIDIA GPUs
- Alert receiver extended to email or chat for the admin on duty
- Longer alert durations to reduce false positives
- Recovery path: an out-of-band console (IPMI, iDRAC, or physical access) replaces Multipass snapshots

## Questions for Professor Chan
1. How many machines, which OS, and do they have GPUs?
2. Who are the users, and how do they log in today (keys, passwords, campus SSO)?
3. Are the machines reachable from outside campus, or only via VPN?
4. What workloads are normal (Jupyter, training jobs, containers)?
5. Is there existing university IT monitoring or security policy we must follow?
6. Who is notified when something is found, and within what time?
7. Can a staging machine be used to test changes before production?
8. Is there out-of-band console access (IPMI, iDRAC) if SSH breaks?

## Rule
Nothing from this repo is applied to DASH machines without the owner's approval and a tested rollback path.
