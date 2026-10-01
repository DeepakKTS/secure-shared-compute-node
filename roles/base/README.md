# Role: base

Runs on every lab VM (node, monitor, attacker).

## What it addresses

- **T1 (external compromise) and T2 (compromised account):** kernel settings that make local exploits and spoofed traffic harder. Kernel addresses are hidden, there is no unprivileged eBPF, users cannot ptrace other users' processes, setuid programs do not dump core, planted files in shared `/tmp` cannot be used against another user, and the host ignores ICMP redirects and source routes.
- **Evidence you can trust:** chrony on every VM, so scenario start times and alert receive times come from the same kind of clock. In the lab, chrony steps the clock on any offset over 1 s, because VM clocks can lag by minutes after the host laptop sleeps. All VMs run in UTC.
- **No core dumps (T2, T3):** a core file can hold passwords, keys and other users' data. Ubuntu's crash reporter, apport, takes every crash through a `core_pattern` pipe. When it starts at boot it also sets `fs.suid_dumpable=2`, which undid this role's `0` after the first reboot. So the role sets `enabled=0` in `/etc/default/apport` and stops and masks all four apport units (`apport.service`, `apport-forward.socket`, `apport-autoreport.path`, `apport-autoreport.timer`). It sets `kernel.core_pattern = core`, a plain file name, because the kernel obeys the core size limit for a file but runs a pipe helper whatever the limit. The hard and soft core limit is 0 for login, SSH, cron and su sessions (`/etc/security/limits.d/60-ssc-core.conf`, with root listed by name, since the wildcard does not cover root), and for services (`DefaultLimitCORE=0`). The cost is that the server keeps no crash reports in `/var/crash`.
- **Patches that take effect:** needrestart restarts services after a library upgrade without asking. Without it, an unattended upgrade can leave a patched library unused until someone restarts the service.

Each kernel setting has its reason next to it in `defaults/main.yml`. Two settings that Lynis suggests are left out on purpose:
- `kernel.modules_disabled=1` blocks loading any kernel module until reboot, and nftables and fail2ban need modules.
- `kernel.core_uses_pid` only changes core file names.

## Variables

| Variable | Default | Notes |
|---|---|---|
| `base_packages` | chrony, needrestart | |
| `base_timezone` | `Etc/UTC` | set in `inventory/group_vars/all.yml` |
| `base_ntp_pools` | Ubuntu pools | DASH would use campus NTP servers |
| `base_chrony_makestep` | `1 -1` | lab value; Ubuntu's default is `1 3` |
| `base_rp_filter` | `1` (strict) | use `2` (loose) on multi-homed servers with asymmetric routing |
| `base_sysctl` | see `defaults/main.yml` | key: value, written to `/etc/sysctl.d/99-zz-ssc-hardening.conf` |

## Ubuntu 24.04 details

- The role owns all of `/etc/chrony/chrony.conf`. A `conf.d` drop-in is not enough, because Ubuntu's file reads `conf.d` near the top and sets `makestep 1 3` further down.
- systemd-sysctl applies `sysctl.d` files in name order across `/etc`, `/run` and `/usr/lib`, and the last value wins. Ubuntu's `/usr/lib/sysctl.d/99-protect-links.conf` sets `fs.protected_fifos = 1`, which silently undid the first version of this role (a `60-` file). The file is named `99-zz-ssc-hardening.conf` so it applies last. The tests check live values, which is how this was caught.
- The kernel uses the larger of `net.ipv4.conf.all.rp_filter` and the per-interface value. Ubuntu sets every interface to 2, so the file also sets `net.ipv4.conf.*.rp_filter`. Only systemd-sysctl understands that glob, so the handler restarts `systemd-sysctl`.

## How to verify

```
make harden TAGS=base
make harden TAGS=base        # second run: changed=0
make reboot                  # boot-time units must not undo anything
PATH=.venv/bin:$PATH .venv/bin/pytest -m lab tests/test_base.py
```

The tests check live values: `sysctl` (including the default-route interface's `rp_filter`), chrony's parsed config (`chronyd -p`), sync state (`chronyc tracking`), and the timezone (`timedatectl`).
