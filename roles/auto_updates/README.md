# Role: auto_updates

Runs on the node and the monitor.

## What it addresses

**T1 (external compromise), the unpatched-service path.** Most break-ins use a bug that already has a fix. A shared research server is often left alone for weeks, so security fixes must go in without waiting for an admin. unattended-upgrades installs them once a day.

## What it sets, and why

- **Daily runs** (`20auto-upgrades`): `apt-daily.timer` refreshes the package lists and `apt-daily-upgrade.timer` installs fixes. Both timers are enabled and started. `AutocleanInterval` clears downloaded packages every `auto_updates_autoclean_days`, so `/var/cache/apt` does not fill the disk.
- **Security fixes only** (`52ssc-unattended-upgrades`, origins in `auto_updates_origins`). That means the security pocket, Ubuntu Pro's security pockets (used only on a machine attached to Pro), and the release pocket. The release pocket is frozen on release day. It stays because a security fix can need a new dependency that only the release pocket has. `-updates`, `-proposed` and `-backports` are left out: they change features, and on a server people depend on, the admin schedules those.
- **The list is the whole list.** apt.conf lists add up across files, so a line in the package's `50unattended-upgrades`, or one an admin uncomments there, would quietly widen it. The role's file comes later (`52`) and starts with `#clear`. A test shows the effect: a probe file before ours that adds `-updates` is cleared, and one after ours is caught.
- **No automatic reboot.** A reboot cuts off every researcher's running jobs, so the admin picks the time. The cost is that a kernel or libc fix protects only after the reboot. `/var/run/reboot-required` shows that one is due; P4.9 turns it into a metric and P5.7 into an alert.
- **Old kernels are removed**, because a full `/boot` breaks the next kernel update.
- **Mail is optional** (`auto_updates_mail`, empty by default). It needs a working mail setup on the host, which this role does not install.
- **`unattended-upgrades.service` stays enabled.** It holds a shutdown until a running upgrade has finished, so a reboot never leaves dpkg half done.
- Each file is parsed with `apt-config -c <file> dump` before it is written. A syntax error in `apt.conf.d` stops every apt command, security updates included. apt-config catches a missing `;` or an open string, but it accepts a stray `}`, so the tests also check the parsed values.

The first run after this role is the next timer run. The role does not upgrade packages during `make harden`. To install pending fixes at once: `sudo unattended-upgrade -v`.

`make harden` and the daily run can overlap. The apt module waits for the dpkg lock.

## Variables

| Variable | Default | Notes |
|---|---|---|
| `auto_updates_origins` | security origins (above) | `${distro_id}` and `${distro_codename}` are expanded by unattended-upgrades |
| `auto_updates_mail` | `""` | set in `inventory/group_vars/all.yml`; empty means no mail |
| `auto_updates_mail_report` | `on-change` | `always`, `only-on-error` or `on-change` |
| `auto_updates_autoclean_days` | `7` | |

## How to verify

```
make harden TAGS=auto_updates
make harden TAGS=auto_updates      # second run: changed=0
make reboot HOSTS=node:monitor     # timers come back at boot
PATH=.venv/bin:$PATH .venv/bin/pytest -m lab tests/test_auto_updates.py
```

The tests read `apt-config dump` for each setting, and run `unattended-upgrade --dry-run --debug` to see the origins it will really use, after it expands the variables. The dry run changes no packages.
