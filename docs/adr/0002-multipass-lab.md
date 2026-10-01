# ADR 0002: Multipass for the local lab

Status: accepted

Context: Needs to run on the author's laptop for free. VirtualBox is limited on Apple Silicon. Vagrant adds a layer.

Decision: Multipass with cloud-init, three VMs, scripted by `scripts/lab.sh`.

Consequences: Works on macOS, Linux, Windows. `multipass exec` and `multipass shell` are not an out-of-band console. They log in over the VM's sshd on port 22, as `ubuntu`, with Multipass's own key. A bad sshd, firewall, or fail2ban change blocks them too. So the `ubuntu` user stays in the `sudo` group, `lab_controller_ip` is always allowed, and a Multipass snapshot (taken with the VM stopped) is the rollback path. Check that the host's Multipass driver supports snapshots in Phase 0. On an Apple Silicon host the VMs are arm64. Nested virtualization and GPUs are not available, so GPU detection is designed but not demonstrated. Falco's modern eBPF driver needs a recent kernel with BTF, which Ubuntu 24.04 has; `lab_check.yml` reports it, verify in Phase 5 and record if it fails.
