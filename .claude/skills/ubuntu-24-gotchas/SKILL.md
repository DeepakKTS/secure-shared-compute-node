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
- `ufw.service` shows enabled and active even when ufw itself is inactive (`ENABLED=no`); it is a oneshot. Mask it anyway.
- Ubuntu's `/etc/nftables.conf` starts with `flush ruleset`, and `nftables.service` has `ExecStop=/usr/sbin/nft flush ruleset`. Both wipe every table, including fail2ban's bans. Replace only your own table (`table X` / `delete table X` / define, in one file, one transaction), and reload the service, never restart it.
- With a default-drop input policy, allow DHCP replies (`udp sport 67 dport 68`, and DHCPv6 547 to 546 from `fe80::/10`). Otherwise the lease cannot renew and the VM loses its address hours later. `nftables.service` runs before `network-pre.target`, so the rules are already active during boot-time DHCP.
- A closed port already answers with a reset, so "only 22 open" in a scan does not prove a firewall. Check that closed ports time out (dropped), and that a fresh listener on a high port is unreachable from another host.

## apt
- `needrestart` may prompt during non-interactive upgrades. Set `NEEDRESTART_MODE=a` in the environment for apt tasks, or configure `/etc/needrestart/conf.d/`.
- unattended-upgrades is usually preinstalled; configure, do not assume defaults.
- apt.conf lists add up across `apt.conf.d` files. A later file that sets `Unattended-Upgrade::Allowed-Origins` appends to the vendor list; start it with `#clear Unattended-Upgrade::Allowed-Origins;` to replace it. `#` lines are comments, except `#clear` and `#include`. Verified in Phase 2.
- `apt-config -c <file> dump` exits 100 on a missing `;`, an open string or an open list, but accepts a stray `}`. Use it as `validate:`, and test the parsed values too. Verified in Phase 2.
- `unattended-upgrade --dry-run --debug` prints `Allowed origins are: ...` after expanding `${distro_id}`; it changes no packages and takes a few seconds.

## /tmp
- /tmp is on the root filesystem by default, not tmpfs. To mount it noexec, enable systemd's `tmp.mount` with a drop-in setting `Options=mode=1777,strictatime,nosuid,nodev,noexec`, or an fstab entry. Reboot or remount and confirm with `findmnt /tmp`.
- noexec blocks `./binary`, not `sh script` or `python script`. Do not claim otherwise.
- /dev/shm: add fstab or mount unit options `noexec,nosuid,nodev`. systemd-remount-fs applies them at boot. Verified in Phase 2.
- noble ships `tmp.mount` only in `/usr/share/systemd/`, not as a unit. An fstab entry for `/tmp` is simpler; systemd turns it into `tmp.mount`. Verified in Phase 2.
- Ansible unpacks every module into the system temp dir (`tempfile.mkdtemp()` in the AnsiballZ wrapper), not remote_tmp. A task that mounts over `/tmp` loses its own result ("No start of json char found"). Give that task `environment: {TMPDIR: /var/tmp}`. Verified in Phase 2.
- A noexec `/tmp` does not break apt on noble: `dpkg-preconfigure` extracts config scripts to `/var/cache/debconf/tmp.ci`, not `/tmp`. Only `apt-extracttemplates` run by hand defaults to `/tmp`. Verified in Phase 2 with a real noexec `/tmp` and a package with a debconf config script.
- `ansible.posix.mount` with `state: absent` also deletes the mount point. To undo a `/tmp` mount, use `state: absent_from_fstab`, then `umount`.

## fail2ban
- sshd logs go to journald. Use `backend = systemd` and install `python3-systemd`.
- Use `banaction = nftables-multiport`. Bans go into `table inet f2b-table` (chain at input priority -1), created on the first ban, not at start. Confirm a ban in nftables (`nft list set inet f2b-table addr-set-sshd`), not only in `fail2ban-client status sshd`: see the next point.
- fail2ban 1.0.2 (noble) loses a jail's action when a reload changes it. The package starts with its own `banaction = nftables`. A reload to `nftables-multiport` then leaves the jail with no action. It still logs "Ban" and counts bans in `status`, and nothing is blocked. Restart instead of reload after a config change, and check the running action with `fail2ban-client get sshd action nftables-multiport actionban`. `get sshd actions` says "No actions" even when the action is there, so do not use it. Verified in Phase 2.
- The stock sshd journal match is `_SYSTEMD_UNIT=sshd.service + _COMM=sshd`. Ubuntu's unit is `ssh.service`, so only `_COMM=sshd` matches, and any local user can set that (`prctl(PR_SET_NAME)`) and forge failure lines naming any address. Override it in `filter.d/sshd.local` with `journalmatch = _SYSTEMD_UNIT=ssh.service`. sshd's pre-login lines all carry that field; post-login lines sit in `session-N.scope`. Verified in Phase 2.
- Whitelist the admin host (`lab_controller_ip`) and monitor with `ignoreip` so testing does not lock you out. Banning the controller also breaks `multipass exec`.
- With key-only sshd there are no `Failed password` lines. In the default `normal` mode the sshd filter counts `Invalid user ...`, `... not allowed because none of user's groups are listed in AllowGroups` (root is outside AllowGroups), and similar. It does not count `Connection closed by authenticating user ... [preauth]` (a valid user with no accepted key; NOFAIL in this mode), or the port scan's `banner exchange ... invalid format` (counted only in `ddos` mode). Verified in Phase 2 with real lines. So S1 must use user names that do not exist, or root.
- In fail2ban-regex output, `Failregex: N total` also counts NOFAIL and `Accepted` hits. To check that lines are counted as failures, feed it only those lines.

## auditd
- Rules in `/etc/audit/rules.d/*.rules`, loaded by `augenrules --load`.
- Do not set `-e 2` (immutable) during development; it makes rule changes need a reboot. Add it only as a documented optional final step.
- Tag every rule with `-k ssc_<purpose>` so `ausearch -k` works in tests and scenarios.
- `~` is not expanded in audit rules, and a watch needs its parent directory to exist. Render per-user watches (`/home/alice/.config/systemd`, rc files) from `users_research`, and create the directories first.
- `ausearch` reads stdin when stdin is not a terminal (testinfra, `ssh host cmd`, cron), so it finds nothing and prints `<no matches>`. Add `--input-logs` to read the log from auditd.conf. Verified in Phase 2.
- `auditctl -l` prints a mode mask in hex: `-F a1&06000` comes back as `-F a1&0xC00`. Watches print as written, with no trailing slash. Verified in Phase 2.

## chrony
- Install chrony on all VMs so scenario timing uses one time source.
- The default `makestep 1 3` only steps the clock in the first three updates after start. After the host laptop sleeps, a VM clock can lag by minutes, and slewing it back is slow. In the lab, set `makestep 1 -1` (step on any offset over 1 s). Verify after a sleep in Phase 2.
- A `conf.d` drop-in cannot change `makestep`. The noble `chrony.conf` reads `confdir /etc/chrony/conf.d` near the top and sets `makestep 1 3` further down. Template the whole file (roles/base does).
- chronyd runs under an AppArmor profile (`/usr/sbin/chronyd`) that only lets it read its own paths. `validate: chronyd -p -f %s` then fails with "Permission denied" on Ansible's temp file, even as root. Validate with `/usr/bin/aa-exec -p unconfined -- /usr/sbin/chronyd -p -f %s`; `-p` only parses and exits. Expect the same for other confined daemons.

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
