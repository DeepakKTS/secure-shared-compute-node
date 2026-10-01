# Role: ssh_hardening

Runs on the node and the monitor.

## What it addresses

**T1 (external compromise), the brute-force and stolen-password path.** SSH is the one service every shared server exposes, so it is the first thing an attacker tries.

- **Keys only** (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`): there is no password to guess, phish or reuse from another breach.
- **No root login** (`PermitRootLogin no`): admins log in as themselves and use sudo, so every root action traces to a person.
- **`AllowGroups sudo ssc-users`**: only admins (and `ubuntu`) and research users may log in, so a system or service account that gains a key by mistake still cannot.
- **`MaxAuthTries 3`, `LoginGraceTime 30`**: fewer guesses per connection, and half-open logins cannot hold every connection slot. fail2ban (P2.5) bans repeat offenders.
- **No X11 or agent forwarding**: either one lets someone with root on this server use the connecting user's display or SSH keys.
- **`ClientAliveInterval 300`**: dead sessions are closed instead of lingering.

Port 22 stays. Moving it is obscurity, not security, and on Ubuntu 24.04 the port belongs to `ssh.socket`.

## Never lock out (CLAUDE.md rule 4)

- `sudo` is in `AllowGroups`, and the admin and `ubuntu` are in `sudo` (role `users`). `multipass exec` logs in as `ubuntu`, so it keeps working.
- No custom `AuthorizedKeysFile`: Multipass and cloud-init write keys to the default place.
- The drop-in is checked with `sshd -t -f` before it is written, and the full configuration with `sshd -t` before sshd reloads. Then the role opens a new connection and pings, because ControlPersist would otherwise reuse the old one.
- Take a snapshot first (`scripts/lab.sh snapshot pre-ssh`), and keep an SSH session open until a new one works.

## Ubuntu 24.04 details

- The drop-in is `/etc/ssh/sshd_config.d/00-hardening.conf`. sshd keeps the first value it reads, and the cloud image ships `60-cloudimg-settings.conf`, so `00-` wins.
- sshd is socket-activated: `ssh.socket` owns port 22 and starts `ssh.service`, which takes the reload.

## Variables

| Variable | Default | Notes |
|---|---|---|
| `ssh_hardening_allow_groups` | `sudo`, `users_research_group` | |
| `ssh_hardening_max_auth_tries` | `3` | |
| `ssh_hardening_login_grace_time` | `30` | seconds |
| `ssh_hardening_client_alive_interval` | `300` | seconds |

## How to verify

```
make harden TAGS=ssh_hardening
make harden TAGS=ssh_hardening    # second run: changed=0
make reboot HOSTS=node:monitor
PATH=.venv/bin:$PATH .venv/bin/pytest -m lab tests/test_ssh_hardening.py
scripts/lab.sh check
```

The tests read `sshd -T` (the settings sshd is using, not the file), try a password login from the attacker, and open new admin, research user and `multipass exec` connections.
