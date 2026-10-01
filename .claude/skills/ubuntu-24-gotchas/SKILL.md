---
name: ubuntu-24-gotchas
description: Known Ubuntu 24.04 (noble) behaviors that break naive hardening. Read before touching SSH, firewall, apt, /tmp, fail2ban, auditd, chrony, user slices, or Multipass cloud-init.
---

# Ubuntu 24.04 gotchas

Verify each on the lab VM before relying on it; record anything that differs.

## SSH
- **Socket activation.** On recent Ubuntu, sshd can be started by `ssh.socket`. Changing `Port` or `ListenAddress` in sshd_config may not take effect; the socket unit owns the listening port. This project keeps port 22 (port changes are obscurity, not security), so avoid the issue. If a port change is ever needed, edit `ssh.socket` via a drop-in.
- **Drop-in precedence.** `/etc/ssh/sshd_config` includes `/etc/ssh/sshd_config.d/*.conf` near the top, and sshd uses the first value it reads for most options. Cloud images may ship `50-cloud-init.conf` that sets `PasswordAuthentication yes`. Name the project drop-in `00-hardening.conf` so it wins, and confirm with `sshd -T | grep -i passwordauthentication`.
- Reload with `systemctl reload ssh` (service name is `ssh`, not `sshd`).
- **MaxAuthTries and ssh-agent.** With `MaxAuthTries 3`, a client whose agent holds several keys can fail with "Too many authentication failures" before it tries the right key. It looks like a lockout. The generated inventory and `.lab/ssh_config` set `IdentitiesOnly=yes`.
- **ControlPersist.** Ansible reuses its SSH connection, so a task after an sshd reload does not prove a new login works. Use `meta: reset_connection`, then a ping, then `ssh -o ControlPath=none` from the controller.

## Firewall
- ufw is installed by default. Disable it (`ufw disable`, then mask or remove) before enabling the nftables service, so two tools do not manage rules.
- Enable `nftables.service` so rules load at boot. Check with `nft list ruleset` after a reboot.

## apt
- `needrestart` may prompt during non-interactive upgrades. Set `NEEDRESTART_MODE=a` in the environment for apt tasks, or configure `/etc/needrestart/conf.d/`.
- unattended-upgrades is usually preinstalled; configure, do not assume defaults.

## /tmp
- /tmp is on the root filesystem by default, not tmpfs. To mount it noexec, enable systemd's `tmp.mount` with a drop-in setting `Options=mode=1777,strictatime,nosuid,nodev,noexec`, or an fstab entry. Reboot or remount and confirm with `findmnt /tmp`.
- noexec blocks `./binary`, not `sh script` or `python script`. Do not claim otherwise.
- /dev/shm: add fstab or mount unit options `noexec,nosuid,nodev`.

## fail2ban
- sshd logs go to journald. Use `backend = systemd` and install `python3-systemd`.
- Use `banaction = nftables-multiport`. Confirm bans with `fail2ban-client status sshd` and `nft list ruleset`.
- Whitelist the admin host (`lab_controller_ip`) and monitor with `ignoreip` so testing does not lock you out. Banning the controller also breaks `multipass exec`.
- With key-only sshd there are no `Failed password` lines. In the default `normal` mode the sshd filter counts lines such as `Invalid user ...` and `... not allowed because none of user's groups are listed in AllowGroups`. A login to an existing, allowed account without its key may not count. Check the real log lines with `fail2ban-regex systemd-journal sshd` before writing S1 (verify in Phase 2).

## auditd
- Rules in `/etc/audit/rules.d/*.rules`, loaded by `augenrules --load`.
- Do not set `-e 2` (immutable) during development; it makes rule changes need a reboot. Add it only as a documented optional final step.
- Tag every rule with `-k ssc_<purpose>` so `ausearch -k` works in tests and scenarios.
- `~` is not expanded in audit rules, and a watch needs its parent directory to exist. Render per-user watches (`/home/alice/.config/systemd`, rc files) from `users_research`, and create the directories first.

## chrony
- Install chrony on all VMs so scenario timing uses one time source.
- The default `makestep 1 3` only steps the clock in the first three updates after start. After the host laptop sleeps, a VM clock can lag by minutes, and slewing it back is slow. In the lab, set `makestep 1 -1` (step on any offset over 1 s). Verify after a sleep in Phase 2.

## systemd user slices
- `user-.slice.d/` drop-ins apply to every `user-<uid>.slice`, including the admin.
- sudo does not change cgroups. Ansible's `become` tasks stay in the admin's slice, so exempt the admin (and `ubuntu`) with `user-<uid>.slice.d/` overrides.
- `pam_systemd` runs only for interactive sessions (it is not in `common-session-noninteractive`). User cron and at jobs therefore run in the cgroups of `cron.service` and `atd.service`, not the user slice. Cap those services too. Verify with `systemd-cgls` in Phase 3.

## Multipass
- Pass the admin public key through cloud-init `ssh_authorized_keys`. Keep the `default` user in the `users:` list, or Multipass loses its `ubuntu` login.
- `multipass exec` and `multipass shell` are not out-of-band. They log in over the VM's sshd on port 22, as `ubuntu`, with Multipass's own key. If sshd, nftables, or fail2ban blocks that, they fail too. Keep `ubuntu` in `sudo` (it passes `AllowGroups sudo ...`), do not set a custom `AuthorizedKeysFile`, and always allow `lab_controller_ip`.
- The real rollback is a snapshot: `scripts/lab.sh snapshot <name>` (the VM must be stopped; lab.sh stops and restarts it). Restore with `multipass restore --destructive ssc-node.<name>`, which needs explicit confirmation.
- VM IPs can change after restart; always regenerate the inventory in `make lab-up`.
- Recreated VMs get new host keys. The inventory uses `.lab/known_hosts` with `StrictHostKeyChecking=accept-new`, and `lab-down` clears it.
- `multipass list --format json` gives IPv4 addresses but no netmask. `gen_inventory.py` takes `lab_cidr` from the host's Multipass bridge (the interface holding the controller IP), at most a /24, and uses each VM's address inside it. Other VM tools can also create `bridge1xx` interfaces on macOS; the controller IP from `multipass exec` picks the right one.
- On an Apple Silicon host, the VMs are arm64.
- Multipass VMs take the host's timezone (a macOS host in New York gives `America/New_York`). Tools that print local time with no zone, such as Lynis report dates, then drift from UTC. Run them with `TZ=UTC`, and use UTC epoch times for scenario timing. Decide in Phase 2 whether `base` should set the VMs to UTC.
