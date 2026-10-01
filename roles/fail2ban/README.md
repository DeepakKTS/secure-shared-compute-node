# Role: fail2ban

Runs on the node and the monitor.

## What it addresses

**T1 (external compromise), the SSH brute-force path.** sshd already accepts keys only (role `ssh_hardening`), so there is no password to guess. fail2ban covers what is left. A host that keeps trying user names that do not exist, or `root`, is probing for a weak account. After `fail2ban_maxretry` such failures within `fail2ban_findtime`, its address is banned from port 22 for `fail2ban_bantime`. This cuts log noise, slows user name discovery, and gives scenario S1 a clear, checkable response.

## How it is set up, and why

- **Journal, not log files** (`backend = systemd`, with `python3-systemd`). sshd on Ubuntu 24.04 logs only to the journal.
- **The journal match is the unit** (`_SYSTEMD_UNIT=ssh.service`, file `filter.d/sshd.local`). The stock match is `_SYSTEMD_UNIT=sshd.service + _COMM=sshd`. On Ubuntu the unit is `ssh.service`, so only the `_COMM` part matched, and any local user can name a process `sshd` and write to syslog. In the lab, every such line forged by the user `nobody` counted as a failure with the stock match, so a user could get any address banned, such as another researcher's. journald sets `_SYSTEMD_UNIT` itself, and none of the forged lines match it. sshd's pre-login lines all come from `ssh.service`.
- **Bans go into fail2ban's own nftables table** (`banaction = nftables-multiport`). fail2ban creates `table inet f2b-table` with a chain at input priority -1, which runs before the firewall's `inet ssc_filter` table. A banned address gets a reject on port 22. The firewall role replaces only its own table on reload, so bans stay. Bans are kept in fail2ban's database (`/var/lib/fail2ban/fail2ban.sqlite3`) and come back after a restart or a reboot.
- **`mode = normal`**. This counts invalid users, users outside `AllowGroups`, and `root`. It does not count a valid user whose key was refused ("Connection closed by authenticating user ... [preauth]" is a NOFAIL line in this mode). A researcher with a broken key setup is not banned, which matters on a campus where many users share one NAT address. `aggressive` would also count port scans and dropped handshakes.
- **The handler restarts, it does not reload.** In fail2ban 1.0.2, a reload that changes a jail's ban action leaves the jail with no action at all. It still logs "Ban", but nothing is blocked. This happened on the first run here: the package started with its own action (`nftables`), and the reload to `nftables-multiport` lost both. A restart loads the actions fresh and restores current bans from the database. The role also asks the running jail for its action on every run, and restarts a jail that has lost it.
- **Configuration is checked before it is written.** Each file is tested with `fail2ban-client -t` on a copy of `/etc/fail2ban` that holds the new file.

## Never lock out (CLAUDE.md rule 4)

- `ignoreip` always holds `lab_controller_ip` and the monitor's address, plus loopback. The controller runs Ansible, and `multipass exec` comes from it too. The list is built in the tasks from the inventory, not taken from a variable, so an override cannot drop the controller.
- The play stops before installing anything if `lab_controller_ip` or the monitor group is missing.
- After a change, the role reads the running jail's ignore list and fails if the controller is not in it.
- The attacker VM is left out of `ignoreip` on purpose: S1 needs it bannable. The node is not in the monitor's list either. A compromised node should not get free tries at the monitor.
- `firewall_admin_cidrs` (campus or VPN ranges) are not ignored. A compromised host on campus is still banned.
- For a first apply on a live server, schedule a way back before you start, and cancel it once a new login works. Stopping fail2ban removes its table, and with it every ban:
  ```
  sudo systemd-run --unit=ssc-f2b-deadman --on-active=15min /bin/systemctl stop fail2ban
  # ... apply, test a new login ...
  sudo systemctl stop ssc-f2b-deadman.timer
  ```

## Variables

| Variable | Default | Notes |
|---|---|---|
| `fail2ban_maxretry` | `3` | set in `inventory/group_vars/all.yml` |
| `fail2ban_findtime` | `10m` | set in `inventory/group_vars/all.yml` |
| `fail2ban_bantime` | `1h` | set in `inventory/group_vars/all.yml` |
| `fail2ban_sshd_port` | `22` | |
| `fail2ban_sshd_mode` | `normal` | see above before changing |
| `fail2ban_sshd_journalmatch` | `_SYSTEMD_UNIT=ssh.service` | keep it on a field journald sets |
| `lab_controller_ip`, monitor group | from `inventory/lab.yml` | required |

## How to verify

```
make harden TAGS=fail2ban
make harden TAGS=fail2ban      # second run: changed=0
make reboot HOSTS=node:monitor # the jail starts at boot, bans come back
PATH=.venv/bin:$PATH .venv/bin/pytest -m lab tests/test_fail2ban.py
scripts/lab.sh check
```

The tests read the running jail (journal match, action, limits, ignore list). They forge `sshd` lines as a local user and check that nothing is counted. They also rehearse S1: logins from the attacker as a user that does not exist, until it is banned. Then they check that `fail2ban-regex` matches every one of those lines, that the ban is in `f2b-table`, and that the attacker's next connection is refused. They check that a firewall reload keeps the ban and that the controller still gets in. Lifting the ban opens SSH to the attacker again.

Tests that make refused logins from the attacker use the `attacker_unbanned` fixture (`tests/conftest.py`), so a ban never leaks into the next test.
