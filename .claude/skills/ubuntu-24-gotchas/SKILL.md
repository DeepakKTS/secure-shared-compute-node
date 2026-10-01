---
name: ubuntu-24-gotchas
description: Known Ubuntu 24.04 (noble) behaviors that break naive hardening. Read before touching SSH, firewall, apt, /tmp, fail2ban, auditd, or Multipass cloud-init.
---

# Ubuntu 24.04 gotchas

Verify each on the lab VM before relying on it; record anything that differs.

## SSH
- **Socket activation.** On recent Ubuntu, sshd can be started by `ssh.socket`. Changing `Port` or `ListenAddress` in sshd_config may not take effect; the socket unit owns the listening port. This project keeps port 22 (port changes are obscurity, not security), so avoid the issue. If a port change is ever needed, edit `ssh.socket` via a drop-in.
- **Drop-in precedence.** `/etc/ssh/sshd_config` includes `/etc/ssh/sshd_config.d/*.conf` near the top, and sshd uses the first value it reads for most options. Cloud images may ship `50-cloud-init.conf` that sets `PasswordAuthentication yes`. Name the project drop-in `00-hardening.conf` so it wins, and confirm with `sshd -T | grep -i passwordauthentication`.
- Reload with `systemctl reload ssh` (service name is `ssh`, not `sshd`).

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
- Whitelist the admin host and monitor with `ignoreip` so testing does not lock you out.

## auditd
- Rules in `/etc/audit/rules.d/*.rules`, loaded by `augenrules --load`.
- Do not set `-e 2` (immutable) during development; it makes rule changes need a reboot. Add it only as a documented optional final step.
- Tag every rule with `-k ssc_<purpose>` so `ausearch -k` works in tests and scenarios.

## Multipass
- Pass the admin public key through cloud-init `ssh_authorized_keys`.
- `multipass exec ssc-node -- sudo bash` is the recovery console if SSH breaks.
- VM IPs can change after restart; always regenerate the inventory in `make lab-up`.
