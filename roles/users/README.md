# Role: users

Runs on the node and the monitor. Research users exist only on the node. The monitor gets the admin and `ubuntu` only (`inventory/group_vars/monitor.yml`), because a research user who could log in to the monitor could reach the alert pipeline that watches the node.

## What it addresses

- **T2 (compromised research account) and T3 (insider misuse):** research users have no sudo, and their only extra group is `ssc-users`. A stray `sudo`, `adm` or `lxd` membership is removed on the next run. So a stolen research key gives normal user rights, not root.
- **One user reading another's files:** home directories are `0700`. Ubuntu's default `HOME_MODE` is `0750`.
- **Keys added behind the admin's back:** each research user's `authorized_keys` is managed with `exclusive: true`, so a key planted outside Ansible is removed on the next run.
- **The sudo policy is code, not whatever cloud-init wrote.** The role rewrites `/etc/sudoers.d/90-cloud-init-users` (validated with `visudo`). It uses the same file name, so the change is one atomic write and there is never a moment without a working rule.
- **Never lock out (CLAUDE.md rule 4):** the admin and `ubuntu` keep passwordless sudo and stay in `sudo`. `multipass exec` logs in as `ubuntu`. After the sudo policy is written, the role checks sudo again over a new connection.

## Variables

| Variable | Default | Notes |
|---|---|---|
| `users_admin` | `admin_user` | the account Ansible logs in as |
| `users_research` | `[]` | `{name, ssh_public_key}`; the lab sets alice and bob in `group_vars/node.yml` |
| `users_research_group` | `ssc-users` | sshd's `AllowGroups` lists it (P2.3) |
| `users_home_mode` | `0700` | |
| `users_generate_lab_keys` | `false` | the lab sets `true`: a key pair per user in `~/.config/ssc-lab/keys/<name>_ed25519` on the controller |
| `users_lab_key_dir` | `~/.config/ssc-lab/keys` | outside the repo, next to the admin key from `scripts/lab.sh` |
| `users_sudo_nopasswd` | admin, ubuntu | written to `/etc/sudoers.d/90-cloud-init-users` |

On DASH, set `users_generate_lab_keys: false` and give each user's own `ssh_public_key`. The admin's passwordless sudo is a lab convenience. On DASH the admin key should have a passphrase or live on a hardware key.

## How to verify

```
make harden TAGS=users
make harden TAGS=users      # second run: changed=0
PATH=.venv/bin:$PATH .venv/bin/pytest -m lab tests/test_users.py
scripts/lab.sh check        # multipass exec + sudo as ubuntu
```
