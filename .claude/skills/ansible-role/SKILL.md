---
name: ansible-role
description: How to write or change an Ansible role in this repo (hardening, monitoring, detection roles). Use whenever creating or editing anything under roles/, playbooks/, or inventory/group_vars/.
---

# Writing an Ansible role here

## Layout
```
roles/<name>/
  defaults/main.yml     # every tunable, prefixed <name>_
  tasks/main.yml        # entry; include OS-specific files if needed
  handlers/main.yml
  templates/*.j2        # header: "# Managed by Ansible (role: <name>). Do not edit by hand."
  meta/main.yml         # min_ansible_version, platforms: Ubuntu noble
  README.md             # what threat this addresses (T-ID), variables, how to verify
```

## Rules
1. Fully qualified module names: `ansible.builtin.*`, `ansible.posix.*`, `community.general.*`.
2. Prefer modules over `shell`/`command`. When unavoidable, set `changed_when`, and `creates`/`removes` or a check task first. Never leave a command that reports changed on every run.
3. Config files that can break access or services must use `validate:`:
   - sshd: `validate: /usr/sbin/sshd -t -f %s`
   - sudoers: `validate: /usr/sbin/visudo -cf %s`
   - nftables: `validate: /usr/sbin/nft -c -f %s`
   - Prometheus rules: validate with `promtool check rules %s` when promtool is on the host
4. Use handlers for restarts and reloads. Reload over restart where the service supports it.
5. Packages: `ansible.builtin.apt` with `update_cache: true` and `cache_valid_time: 3600`. Pin versions for components listed in docs/VERSIONS.md.
6. Downloaded binaries (exporters, Prometheus): use `ansible.builtin.get_url` with `checksum: sha256:<value from the release's checksum file>`. Never download without a checksum. Map `ansible_architecture` to the upstream name (`aarch64` to `arm64`, `x86_64` to `amd64`) and keep one pinned sha256 per architecture in `defaults/main.yml`. The lab VMs are arm64 on Apple Silicon hosts; CI runs on amd64.
7. Services run as dedicated system users with no login shell, and systemd units include hardening options where they do not break the service: `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `ReadWritePaths=` for data dirs.
8. Secrets never in defaults. Use Ansible Vault or read from `.lab/`.
9. Tags: every role's tasks tagged with the role name so `make harden TAGS=ssh_hardening` works.
10. Say which hosts a role runs on in its README. `base` runs everywhere. The access roles (users, ssh_hardening, firewall, fail2ban, auto_updates) run on node and monitor.

## Verify every change
```
make lint
make harden TAGS=<role>
make idempotency          # second run must be changed=0
pytest tests/test_<role>.py
```
If you touched SSH or firewall: open a new SSH session as admin before ending the task (`ssh -F .lab/ssh_config -o ControlPath=none ssc-node true`), and check `multipass exec ssc-node -- true` still works.

If the role sets boot-time state (sysctl, services, mounts, limits, sshd, nftables, auditd rules), the check is not done until it survives a reboot:
```
make reboot HOSTS=<group>   # waits for `systemctl is-system-running --wait`
pytest -m lab tests/test_<role>.py
scripts/lab.sh check        # multipass exec still works after boot
```
A value that is live right after `make harden` can be undone at boot. In Phase 2 this happened twice: apport reset `fs.suid_dumpable`, and a vendor `sysctl.d` file reset `fs.protected_fifos`. Take the snapshot for an SSH or firewall task before its first reboot.
