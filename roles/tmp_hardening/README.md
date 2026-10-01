# Role: tmp_hardening

Runs on the node.

## What it addresses

**T1 and T2 (an attacker with a foothold, from outside or through a stolen account).** A typical miner dropper works like this: write a binary to a path anyone can write, mark it executable, run it. `/tmp` and `/dev/shm` are the usual choice, because every user can write there and nothing else uses them for programs. Mounting both `noexec` stops that last step. `nosuid` makes setuid bits there count for nothing, and `nodev` does the same for device files.

## What it sets, and why

- **`/tmp` is its own tmpfs**, `mode=1777,strictatime,size=<tmp_hardening_tmp_size>,nosuid,nodev,noexec`, from an fstab entry. On Ubuntu 24.04 `/tmp` is a directory on the root disk. A tmpfs of its own, capped in size, means filling `/tmp` cannot fill the root disk. Anything dropped there is gone at reboot. tmpfs pages count against the memory of the user who wrote them, so the per-user memory cap (Phase 3) also limits each user's share of `/tmp`. systemd mounts it at boot as `tmp.mount`, before the services that use `/tmp`.
- **`/dev/shm` gets `noexec`**, added to its existing `nosuid,nodev` through an fstab entry. systemd applies it at boot by remounting (`systemd-remount-fs`).
- Both take effect at once. The mount module mounts `/tmp` and remounts `/dev/shm`. Mounting `/tmp` hides the old files on the disk below it, while running services keep their own private `/tmp`.
- **The `/tmp` task runs with `TMPDIR=/var/tmp`.** Ansible unpacks every module into the system temp dir. On the first run, the module would mount over its own files, and its result would be lost ("No start of json char found"). This happened on the first apply here.

On DASH, size `/tmp` to the machine, or give it a disk partition with the same options if jobs need large temp files.

## What it does not do

- `noexec` stops `./binary`. It does not stop `sh script`, `python3 script`, or a binary run through the dynamic loader. Those still need the other layers: auditd records exec from temp paths (P2.8), and Falco alerts on it (Phase 5).
- `/var/tmp` stays as it is. It is disk-backed and kept across reboots, and some tools build in it, for example the initramfs tools. The detection layers watch it too.

## apt with noexec /tmp

A noexec `/tmp` is often said to break apt, because debconf config scripts are extracted there and run. This was tested on noble before choosing a fix, with a real noexec `/tmp` and a small package with a debconf config script:
- `apt-extracttemplates` on its own does default to `/tmp`.
- apt does not use that path. It runs `dpkg-preconfigure`, which passes its own `--tempdir /var/cache/debconf/tmp.ci`. The config script ran from there, both alone and during `apt-get install`, with no "Can't exec" errors.

So the role does not set `APT::ExtractTemplates::TempDir`. A test builds such a package and checks where its config script ran, so a future debconf change would show up. With the role applied, one `unattended-upgrade` run installed the pending openssl and libssl3t64 security updates cleanly (docs/PROGRESS.md, P2.7).

## Variables

| Variable | Default | Notes |
|---|---|---|
| `tmp_hardening_tmp_size` | `512M` | set in `inventory/group_vars/node.yml`; tmpfs is RAM |
| `tmp_hardening_options` | `[nosuid, nodev, noexec]` | for both paths |

## How to verify

```
make harden TAGS=tmp_hardening
make harden TAGS=tmp_hardening     # second run: changed=0
make reboot HOSTS=node             # mounts come back at boot
findmnt /tmp; findmnt /dev/shm
PATH=.venv/bin:$PATH .venv/bin/pytest -m lab tests/test_tmp_hardening.py
```

The tests check the live mounts, their fstab entries and the `/tmp` size. They check that alice cannot run a binary she copied to `/tmp` or `/dev/shm`. They also check that apt's preconfigure step runs config scripts outside `/tmp`.

## Undoing it

Remove the fstab entry first, with `ansible.posix.mount` and `state: absent_from_fstab`, then `umount /tmp`. Do not use `state: absent`: it also deletes the mount point, which here is `/tmp` itself.
