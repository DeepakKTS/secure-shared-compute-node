# Role: firewall

Runs on the node and the monitor. Ingress only for now. Egress rules for mining pool ports come in Phase 5 (P5.5), exporter ports from the monitor in Phase 4 (P4.8), and the monitor's own ports in P2.10.

## What it addresses

**T1 (external compromise).** A shared server should accept only the connections it means to. With a default-drop input policy, a service that starts listening by mistake (a debug web server, a database bound to `0.0.0.0`, a miner's control port) is not reachable from the network. And a port scan learns nothing from the closed ports, because they time out instead of refusing.

Rules, in order:
- Loopback, and `established,related` traffic: replies to connections this host made, and ICMP errors for them.
- `invalid` packets are dropped.
- SSH only from `lab_controller_ip` (first, so the admin host is never locked out; `multipass exec` comes from it too), from `lab_cidr`, and from `firewall_admin_cidrs`. The attacker is inside `lab_cidr` on purpose: scenario S1 needs to reach SSH, and fail2ban (P2.5) bans it per address.
- DHCP replies (v4 and v6). Without them the lease cannot renew, and the address is lost hours later, which is a lockout too.
- Ping, rate limited, and IPv6 neighbour discovery.
- Everything else is dropped and logged (rate limited) with the prefix `SSC-INPUT-DROP:`.

## Why nftables, and why this table layout

- nftables, not ufw: ingress and egress rules with named sets (ADR 0004). ufw is preinstalled, so it is switched off and masked, so two tools never manage rules.
- Only the table `inet ssc_filter` is replaced, in one transaction: the file creates the table if missing, deletes it, and defines it again. Ubuntu's default file starts with `flush ruleset`, which would also wipe fail2ban's table and its bans.
- The handler reloads, never restarts. `nftables.service`'s `ExecStop` is `nft flush ruleset`.
- The file is checked with `nft -c -f` before it replaces the old one.

## Never lock out (CLAUDE.md rule 4)

- The play stops before writing anything if `lab_controller_ip` or `lab_cidr` is missing.
- After the reload, the role opens a new connection and pings, because ControlPersist would otherwise reuse the old one.
- For a first apply on a live server, also schedule a rollback before you start, and cancel it once a new login works:
  ```
  sudo systemd-run --unit=ssc-fw-deadman --on-active=15min /usr/sbin/nft delete table inet ssc_filter
  # ... apply, test a new login ...
  sudo systemctl stop ssc-fw-deadman.timer
  ```

## Variables

| Variable | Default | Notes |
|---|---|---|
| `firewall_admin_cidrs` | `[]` | campus or VPN ranges on DASH |
| `firewall_ssh_port` | `22` | |
| `firewall_log_rate` | `10/minute` | rate of `SSC-INPUT-DROP:` log lines |
| `lab_controller_ip`, `lab_cidr` | from `inventory/lab.yml` | required |

## How to verify

```
make harden TAGS=firewall
make harden TAGS=firewall      # second run: changed=0
make reboot HOSTS=node:monitor # rules load at boot, DHCP still works
PATH=.venv/bin:$PATH .venv/bin/pytest -m lab tests/test_firewall.py
scripts/lab.sh check
```

The tests read the live ruleset (`nft list`), check that from the attacker only port 22 answers in a scan of ports 1 to 1024, that closed ports time out instead of refusing, and that a listener started on port 8888 is reachable on the host but not from the attacker.
