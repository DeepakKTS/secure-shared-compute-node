# ADR 0002: Multipass for the local lab

Status: accepted

Context: Needs to run on the author's laptop for free. VirtualBox is limited on Apple Silicon. Vagrant adds a layer.

Decision: Multipass with cloud-init, three VMs, scripted by `scripts/lab.sh`.

Consequences: Works on macOS, Linux, Windows. `multipass exec` gives a recovery console if SSH is locked out. Nested virtualization and GPUs are not available, so GPU detection is designed but not demonstrated. Falco's modern eBPF driver needs a recent kernel with BTF, which Ubuntu 24.04 has; verify in Phase 5 and record if it fails.
