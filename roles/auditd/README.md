# Role: auditd

Runs on the node.

## What it addresses

- **T2 (code run from a temp path after access).** A dropper writes a binary to `/tmp`, `/dev/shm` or `/var/tmp` and runs it. On the node, `/tmp` and `/dev/shm` are noexec (role tmp_hardening), so the run fails, but the attempt is still a sign of compromise. This role records every exec from those paths, the failed ones too.
- **T7 (persistence).** An attacker who got in wants to come back: a cron entry, a systemd unit, a line in a shell rc file, an SSH key. This role records writes to those paths.
- **T8 (privilege escalation).** A setuid root copy of a shell is a classic backdoor. This role records every chmod that sets a setuid or setgid bit.

The records are evidence for the runbook and for scenarios S2 and S5, which find them by key with `ausearch -k <key>`.

## What it records

| Key | What | Rule |
|---|---|---|
| `ssc_exec_tmp` | `execve` and `execveat` of a program under `/tmp`, `/dev/shm`, `/var/tmp` | syscall rule per arch, `-F dir=<path>`, no success filter |
| `ssc_suid` | chmod-family calls whose mode has bit 04000 or 02000 | syscall rule per arch, `-F a1&06000` or `-F a2&06000` |
| `ssc_cron` | writes to `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron` | watch, `-p wa` |
| `ssc_systemd` | writes to `/etc/systemd/system`, `/etc/systemd/user` | watch, `-p wa` |
| `ssc_sudoers` | writes to `/etc/sudoers`, `/etc/sudoers.d` | watch, `-p wa` |
| `ssc_user_persist` | writes to each research user's `~/.config/systemd`, `~/.ssh` and shell rc files | watch, `-p wa`, one per user and path |

### Why the exec rules have no success filter

Many published rule sets add `-F success=1` to exec rules. Here that would hide exactly what matters. On the noexec `/tmp` an exec fails with `EACCES`, and a filter on success drops that record. The failed attempt is what S2 looks for: `ausearch -k ssc_exec_tmp --success no`. A test runs a binary from `/tmp` as alice, sees it refused, and finds that record.

### Why per-user rules

auditd does not expand `~`, so the template writes one rule per research user from `users_research` (`inventory/group_vars/node.yml`). A watch on a directory is recursive only if the directory exists when the rules load. So the role creates `~/.config/systemd` and `~/.ssh` (owner the user, mode 0700) before it writes the rules. Rc files that do not exist yet (`.bash_profile`, `.bash_login`) are still watched: the watch sits on the home directory and catches the file when it is created. Add a user to `users_research` and rerun the role to cover them.

### Syscall rules and architectures (x86_64 on DASH)

A syscall rule applies to one ABI. On x86_64, a 32-bit program uses the i386 syscall table, and a rule with only `arch=b64` does not see it. Attackers use this to slip past audit rules. So on x86_64 every syscall rule needs both `arch=b64` and `arch=b32`. DASH servers are most likely x86_64.

The role renders both there, from `auditd_syscall_arches` (`x86_64: [b64, b32]`). It also uses each table's syscall names: x86_64 has `chmod`, aarch64 does not. A unit test renders the template for both architectures and checks this.

The lab cannot show the b32 path. The lab VMs are arm64 on Apple Silicon, which cannot run 32-bit Arm programs, so the role uses `b64` only there. On a DASH machine, run the record tests in `tests/test_auditd.py` once, and check that `auditctl -l` lists each syscall rule twice.

Watches (`-w`) are not tied to an ABI, so they need no arch.

`fchmodat2` (Linux 6.6) is unknown by name to audit 3.1.2, so the rule uses its number, 452, which is the same on every architecture.

## Kernel settings

These come from the rules template. augenrules keeps only the last `-b`, `-f` and `-e` it reads. The template is named `ssc.rules` so it sorts after the vendor's `audit.rules`, and its values apply.

- **`-e 1`: enabled, not immutable.** `-e 2` locks the rules until the next reboot. Then every rule change needs a reboot, and a mistake in a rule cannot be fixed without one. On DASH, `-e 2` can be added as a last step once the rules are settled. It stops a root attacker from removing rules, but that attacker can still stop auditd or edit its logs (see below).
- **`-f 1`: on failure, log and go on.** If the backlog fills or auditd is gone, the kernel writes "audit: backlog limit exceeded" to its log and drops records. `-f 2` would panic the kernel. On a shared server, that turns an audit problem into an outage for every user.
- **`-b 8192`**: the backlog, the same as the vendor default. Raise it on a busy DASH machine if the kernel log shows lost records (`auditctl -s` shows `lost`).

## auditd.conf: log size and disk actions

The template is the noble default file with these values changed. Every action was chosen on purpose:

| Setting | Value | Why |
|---|---|---|
| `max_log_file`, `num_logs` | 50 MB, 8 files | The audit log takes at most 400 MB of the root disk. `max_log_file_action = ROTATE` drops the oldest file. The vendor default (8 MB x 5) holds little history on a busy server. |
| `space_left`, `space_left_action` | 25%, `SYSLOG` | Early warning in the journal when the disk holding the log gets low. `EMAIL` needs a mail setup the lab does not have; DASH can use it. |
| `admin_space_left`, `admin_space_left_action` | 10%, `ROTATE` | Keep recording, at the cost of the oldest audit files. The vendor default, `SUSPEND`, stops recording, so a user who fills the disk could then act unrecorded. Recent records matter most for detection. |
| `disk_full_action` | `ROTATE` | Same reason: free space by dropping the oldest audit file and keep recording. |
| `disk_error_action` | `SYSLOG` | Report write errors in the journal and keep trying, instead of going quiet until someone resumes auditd. |

No action is `SINGLE` or `HALT`. CIS Level 2 asks for one of them, so that no event goes unrecorded. On a shared research server, any user can fill the disk (homes and `/var/tmp` are on it), so `HALT` would let any user take the node down for everyone. The disk usage alert (P5.6) is meant to fire before these thresholds. A test checks that no action is `single` or `halt`.

`auditd.conf` is a conffile of the auditd package, and this role changes it. If an update ships a new version of the file, dpkg asks which one to keep, and unattended-upgrades does not answer that question. Its handling of such an update has not been seen in the lab yet. After an auditd update, check `/var/log/unattended-upgrades/` and rerun the role.

## What it does not do

- **Scripts run through an interpreter.** `sh /tmp/x.sh` executes `/bin/sh`, so `ssc_exec_tmp` does not match it. noexec has the same gap (role tmp_hardening README). Falco covers this in Phase 5.
- **Root can blind it.** A root attacker can stop auditd, delete rules (unless `-e 2`), or edit `/var/log/audit/`. The logs stay on the node. Central log shipping is in the parking lot (TODO.md). This is why the monitor is a separate VM.
- **File capabilities.** `setcap` gives a binary privileges without a setuid bit. The `ssc_suid` rule does not see that.
- **Noise.** A build that runs programs from `/var/tmp` creates many `ssc_exec_tmp` records. On DASH, check the volume after a week and tune `auditd_exec_paths` if needed.

## Variables

| Variable | Default | Notes |
|---|---|---|
| `auditd_exec_paths` | `[/tmp, /dev/shm, /var/tmp]` | exec from these is recorded |
| `auditd_cron_paths`, `auditd_systemd_paths`, `auditd_sudoers_paths` | see defaults | watched for writes |
| `auditd_user_dirs`, `auditd_user_rc_files` | see defaults | watched under each research user's home |
| `auditd_syscall_arches` | `aarch64: [b64]`, `x86_64: [b64, b32]` | ABIs per architecture |
| `auditd_chmod_syscalls` | see defaults | chmod-family syscalls per architecture, by mode argument |
| `auditd_backlog_limit` | `8192` | kernel backlog |
| `auditd_max_log_file`, `auditd_num_logs` | `50`, `8` | log size cap |
| `auditd_*_action`, `auditd_space_left`, `auditd_admin_space_left` | see the table above | disk actions |

## How to verify

```
make harden TAGS=auditd
make harden TAGS=auditd            # second run: changed=0
make reboot HOSTS=node             # rules come back at boot
PATH=.venv/bin:$PATH .venv/bin/pytest -m lab tests/test_auditd.py
sudo auditctl -l                   # on the node: every ssc_ rule
sudo ausearch -k ssc_exec_tmp --success no -i
```

From a script, over `ssh`, or from cron, add `--input-logs`. When stdin is not a terminal, ausearch reads its records from stdin, not the log, and finds nothing. That looks like a missing record. Seen in the lab: the same search found 2 records with the option and none without it. The tests and scenarios S2 and S5 use it.

The role itself compares the rules the kernel holds with the file, loads them again if they differ, and fails if they still differ. The tests check that, the kernel settings and the auditd.conf values. They also make the records S2 and S5 will look for and find them by key: a refused exec from `/tmp` and `/dev/shm`, an exec from `/var/tmp`, writes to cron, systemd, sudoers and user paths, and setuid and setgid bits set with `chmod` and with `fchmodat2`. A plain chmod must not show up under `ssc_suid`.
