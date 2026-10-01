---
name: falco-rules
description: How to install Falco and write, test, and tune custom Falco rules for miner and intrusion detection. Use for anything under roles/falco, roles/falcosidekick, or detection/falco/.
---

# Falco in this project

## Install
- Use the official falcosecurity apt repository with its signing key. Pin the version in docs/VERSIONS.md.
- Driver: modern eBPF (`engine.kind: modern_ebpf`). If it fails on the VM kernel, record the error and fall back to the kmod or ebpf driver, then note it in ADR 0002.
- Custom rules go in `detection/falco/rules/ssc.yaml`, deployed to `/etc/falco/rules.d/`. Do not edit upstream rule files.
- Output: `json_output: true`, `http_output` enabled, URL pointing at falcosidekick on the monitor. Include hostname in output fields.

## Rules to write
Use macros and lists so DASH can tune without rewriting logic.

- `ssc_temp_paths` list: /tmp, /var/tmp, /dev/shm
- `ssc_miner_names` list: common miner process names (keep it short and documented; names are easy to change, so this is a weak signal)
- `ssc_mining_ports` list: must match `firewall_mining_ports` in group_vars (render both from the same variable)
- Rule `SSC Exec From Temp Or Hidden Path`: spawned_process where exe path or script arg starts with a temp path, or path contains `/.` under /home
- Rule `SSC Known Miner Process Name`
- Rule `SSC User Process Masquerading As Kernel Thread`: user-owned process whose name looks like `kworker`, `kthreadd`, or bracketed names
- Rule `SSC Outbound Connection To Mining Port`: outbound connect where `fd.sport`/`fd.rport` (check the correct field for remote port in the installed version's docs) is in the mining ports list
- Rule `SSC Persistence Write`: open for write on crontabs, `/var/spool/cron`, `/etc/systemd/system`, `~/.config/systemd/user`, shell rc files, `authorized_keys`, by a non-admin user

Priorities: WARNING for single weak signals, CRITICAL for exec-from-temp plus network or known miner name. Tag all rules `ssc`.

## Verify
- Validate: `falco --validate /etc/falco/rules.d/ssc.yaml` (check the exact flag for the installed version with `falco --help`).
- Trigger each rule by hand once, confirm the event in `journalctl -u falco*` and in `alerts.jsonl` on the monitor.
- Field names change between Falco versions. Always check the installed version's field reference before writing a condition; do not rely on memory.
