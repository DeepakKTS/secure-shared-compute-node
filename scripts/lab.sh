#!/usr/bin/env bash
# Create, inspect, snapshot, and delete the lab VMs with Multipass.
#
#   scripts/lab.sh up               create or start the lab VMs
#   scripts/lab.sh down             delete the lab VMs (you type yes on the terminal)
#   scripts/lab.sh status           show lab VMs and local lab files
#   scripts/lab.sh check            prove `multipass exec` and sudo work on each lab VM
#   scripts/lab.sh snapshot <name>  stop, snapshot, and restart each lab VM
#
# Env: LAB_PROFILE (full | small), UBUNTU_IMAGE, NODE_CPUS, NODE_MEM,
# NODE_DISK (same for MONITOR_ and ATTACKER_), LAB_MIN_FREE_GB. There is no
# variable that skips the `down` prompt.
#
# Works with bash 3.2 (the macOS default): no associative arrays, no mapfile.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_DIR="$ROOT/.lab"
KEY="$LAB_DIR/keys/ssc_admin_ed25519"
CLOUD_INIT_TMPL="$ROOT/scripts/cloud-init.yaml.tmpl"
CLOUD_INIT="$LAB_DIR/cloud-init.yaml"
KNOWN_HOSTS="$LAB_DIR/known_hosts"
PY="$ROOT/.venv/bin/python"

# Must match admin_user in inventory/group_vars/all.yml (a unit test checks it).
ADMIN_USER="ssc-admin"
# Every lab VM name. `down` deletes these and nothing else.
ALL_VMS="ssc-node ssc-monitor ssc-attacker"

LAB_PROFILE="${LAB_PROFILE:-full}"
UBUNTU_IMAGE="${UBUNTU_IMAGE:-24.04}"

# VM sizes from CLAUDE.md section 5. Disk sizes are whole gigabytes.
NODE_CPUS="${NODE_CPUS:-2}"
NODE_MEM="${NODE_MEM:-2G}"
NODE_DISK="${NODE_DISK:-15G}"
MONITOR_CPUS="${MONITOR_CPUS:-2}"
MONITOR_MEM="${MONITOR_MEM:-2G}"
MONITOR_DISK="${MONITOR_DISK:-10G}"
ATTACKER_CPUS="${ATTACKER_CPUS:-1}"
ATTACKER_MEM="${ATTACKER_MEM:-1G}"
ATTACKER_DISK="${ATTACKER_DISK:-5G}"

HOST_OS=""

die() {
    echo "lab.sh: $*" >&2
    exit 1
}

info() {
    echo "lab.sh: $*"
}

usage() {
    echo "usage: scripts/lab.sh up | down | status | check | snapshot <name>" >&2
    exit 2
}

lab_vms() {
    case "$LAB_PROFILE" in
        full) echo "ssc-node ssc-monitor ssc-attacker" ;;
        small) echo "ssc-node ssc-attacker" ;;
        *) die "LAB_PROFILE must be full or small, got '$LAB_PROFILE'" ;;
    esac
}

# Prints "cpus memory disk" for a VM.
vm_spec() {
    case "$1" in
        ssc-node) echo "$NODE_CPUS $NODE_MEM $NODE_DISK" ;;
        ssc-monitor) echo "$MONITOR_CPUS $MONITOR_MEM $MONITOR_DISK" ;;
        ssc-attacker) echo "$ATTACKER_CPUS $ATTACKER_MEM $ATTACKER_DISK" ;;
        *) die "unknown lab VM '$1'" ;;
    esac
}

check_host() {
    local arch
    HOST_OS="$(uname -s)"
    arch="$(uname -m)"
    case "$HOST_OS" in
        Darwin | Linux) ;;
        *) die "unsupported host OS '$HOST_OS'. lab.sh supports macOS and Linux." ;;
    esac
    case "$arch" in
        arm64 | aarch64) arch=arm64 ;;
        x86_64 | amd64) arch=amd64 ;;
        *) die "unsupported host architecture '$arch'" ;;
    esac
    info "host: $HOST_OS $arch (lab VMs will be $arch)"
}

require_venv() {
    [ -x "$PY" ] || die "no .venv/ found. Run 'make deps' first."
}

require_multipass() {
    if command -v multipass >/dev/null 2>&1; then
        return 0
    fi
    case "$HOST_OS" in
        Darwin) die "Multipass not found. Install it with: brew install --cask multipass (https://multipass.run)" ;;
        *) die "Multipass not found. Install it with: sudo snap install multipass (https://multipass.run)" ;;
    esac
}

# Prints "name state first-ipv4" for every Multipass instance.
vm_table() {
    multipass list --format json | "$PY" -c '
import json, sys
for vm in json.load(sys.stdin).get("list", []):
    ips = vm.get("ipv4") or ["-"]
    print(vm["name"], vm["state"], ips[0])
'
}

# Prints the state of one VM, or nothing if it does not exist.
vm_state() {
    vm_table | awk -v n="$1" '$1 == n {print $2}'
}

ensure_key() {
    mkdir -p "$LAB_DIR/keys"
    chmod 700 "$LAB_DIR" "$LAB_DIR/keys"
    if [ ! -f "$KEY" ]; then
        ssh-keygen -q -t ed25519 -N "" -C "$ADMIN_USER@ssc-lab" -f "$KEY"
        info "generated admin key $KEY"
    fi
    [ -f "$KEY.pub" ] || die "missing $KEY.pub. Delete $KEY and rerun to make a new pair."
}

render_cloud_init() {
    (
        umask 077
        "$PY" - "$CLOUD_INIT_TMPL" "$KEY.pub" "$ADMIN_USER" >"$CLOUD_INIT" <<'PYEOF'
import sys
from pathlib import Path

tmpl, pub, user = sys.argv[1:]
text = Path(tmpl).read_text()
text = text.replace("@@ADMIN_USER@@", user)
text = text.replace("@@ADMIN_PUBKEY@@", Path(pub).read_text().strip())
if "@@" in text:
    sys.exit("lab.sh: cloud-init template has an unrendered placeholder")
sys.stdout.write(text)
PYEOF
    )
}

# Prints the number of gigabytes in a size like 15G.
gigabytes() {
    local n="${1%G}"
    case "$1" in
        *G) ;;
        *) die "disk size '$1' must be whole gigabytes, like 15G" ;;
    esac
    case "$n" in
        '' | *[!0-9]*) die "disk size '$1' must be whole gigabytes, like 15G" ;;
    esac
    echo "$n"
}

# Multipass disks grow as the VMs use them. Refuse to create VMs whose disks
# could fill the host, because a full disk breaks the VMs and the host.
check_disk() {
    local need=0 vm disk n path avail_kb avail_gb
    for vm in "$@"; do
        disk="$(vm_spec "$vm" | awk '{print $3}')"
        n="$(gigabytes "$disk")"
        need=$((need + n))
    done
    need="${LAB_MIN_FREE_GB:-$need}"
    case "$need" in
        '' | *[!0-9]*) die "LAB_MIN_FREE_GB must be a whole number of gigabytes, like 20; got '$need'" ;;
    esac
    path="$HOME"
    if [ "$HOST_OS" = Linux ] && [ -d /var/snap/multipass ]; then
        path=/var/snap/multipass
    fi
    avail_kb="$(df -Pk "$path" | awk 'NR == 2 {print $4}')"
    case "$avail_kb" in
        '' | *[!0-9]*) die "could not read free disk at $path from df (got '$avail_kb')" ;;
    esac
    avail_gb=$((avail_kb / 1024 / 1024))
    info "free disk at $path: ${avail_gb}G; the new VM disks can grow to ${need}G"
    # Fail closed: if the test itself errors (a number too large), refuse.
    if [ "$avail_gb" -ge "$need" ]; then
        return 0
    fi
    die "not enough free disk (${avail_gb}G free, ${need}G needed). Free space, or set LAB_MIN_FREE_GB to override."
}

forget_host_key() {
    local ip
    ip="$(vm_table | awk -v n="$1" '$1 == n {print $3}')"
    if [ -f "$KNOWN_HOSTS" ] && [ -n "$ip" ] && [ "$ip" != "-" ]; then
        ssh-keygen -R "$ip" -f "$KNOWN_HOSTS" >/dev/null 2>&1 || true
    fi
}

cmd_up() {
    local vms vm state to_create="" cpus mem disk
    check_host
    require_venv
    require_multipass
    vms="$(lab_vms)"
    ensure_key
    render_cloud_init
    for vm in $vms; do
        state="$(vm_state "$vm")"
        case "$state" in
            "") to_create="$to_create $vm" ;;
            Running) info "$vm is already running" ;;
            Stopped | Suspended)
                info "starting $vm"
                multipass start "$vm"
                ;;
            Deleted) die "$vm is deleted but not purged. Run 'multipass recover $vm' to keep it, or purge it yourself." ;;
            *) die "$vm is in state '$state'. Wait for it to settle, then rerun." ;;
        esac
    done
    if [ -n "$to_create" ]; then
        # shellcheck disable=SC2086 # the VM list is meant to split into words
        check_disk $to_create
        for vm in $to_create; do
            read -r cpus mem disk <<<"$(vm_spec "$vm")"
            info "launching $vm (Ubuntu $UBUNTU_IMAGE, $cpus vCPU, $mem RAM, $disk disk)"
            multipass launch "$UBUNTU_IMAGE" --name "$vm" --cpus "$cpus" --memory "$mem" \
                --disk "$disk" --cloud-init "$CLOUD_INIT" --timeout 900
            # A new VM can reuse an old IP with a new host key.
            forget_host_key "$vm"
        done
    fi
    info "lab VMs ready ($LAB_PROFILE profile): $vms"
}

# Deleting the lab needs a typed yes on a terminal. The answer is read from
# /dev/tty, not stdin, so a pipe or redirected input cannot supply it, and no
# flag or variable skips the prompt (CONFIRM is ignored). This stops scripts
# and mistakes, not a determined program: anything that drives a
# pseudo-terminal can still type yes. For agents, the control is the Claude
# Code ask list.
confirm_delete() {
    local answer=""
    if [ -n "${CONFIRM:-}" ]; then
        echo "lab.sh: CONFIRM is ignored. Type yes at the prompt instead." >&2
    fi
    if ! (: </dev/tty) 2>/dev/null; then
        die "refusing to delete the lab VMs: there is no terminal to ask. Run 'make lab-down' in a terminal and type yes."
    fi
    printf 'Delete the lab VMs (%s) and their snapshots? Type yes to continue: ' "$ALL_VMS" >/dev/tty
    read -r answer </dev/tty || answer=""
    [ "$answer" = yes ] || die "not confirmed. Nothing was deleted."
}

cmd_down() {
    local vm existing=""
    # Confirm before anything else, so a missing tool never hides the prompt.
    confirm_delete
    check_host
    require_venv
    require_multipass
    for vm in $ALL_VMS; do
        if [ -n "$(vm_state "$vm")" ]; then
            existing="$existing $vm"
        fi
    done
    if [ -z "$existing" ]; then
        info "no lab VMs to delete"
    else
        info "deleting:$existing"
        # Delete the lab VMs by name only. Never run a bare 'multipass purge':
        # it also purges deleted instances that are not part of the lab.
        # shellcheck disable=SC2086 # the VM list is meant to split into words
        multipass delete --purge $existing
    fi
    rm -f "$ROOT/inventory/lab.yml" "$KNOWN_HOSTS" "$KNOWN_HOSTS.old" "$LAB_DIR/ssh_config" "$CLOUD_INIT"
    info "removed the generated inventory and SSH files; kept the keys in $LAB_DIR/keys"
}

cmd_status() {
    local table vm row f
    check_host
    if command -v multipass >/dev/null 2>&1; then
        require_venv
        table="$(vm_table)"
        printf '%-14s %-10s %s\n' NAME STATE IPV4
        for vm in $ALL_VMS; do
            row="$(echo "$table" | awk -v n="$vm" '$1 == n {print $2, $3}')"
            if [ -z "$row" ]; then
                row="absent -"
            fi
            # shellcheck disable=SC2086 # split "state ip" into two columns
            printf '%-14s %-10s %s\n' "$vm" $row
        done
    else
        echo "multipass: not installed"
    fi
    for f in inventory/lab.yml .lab/ssh_config .lab/keys/ssc_admin_ed25519; do
        if [ -e "$ROOT/$f" ]; then
            echo "$f: present"
        else
            echo "$f: missing"
        fi
    done
}

# `multipass exec` logs in over sshd as `ubuntu`, so it is the recovery path
# CLAUDE.md rule 4 protects, not an out-of-band console. Prove it works, and
# that `ubuntu` can still use sudo, on every lab VM.
cmd_check() {
    local vm state failed=""
    check_host
    require_venv
    require_multipass
    for vm in $(lab_vms); do
        state="$(vm_state "$vm")"
        if [ "$state" != Running ]; then
            echo "lab.sh: $vm is ${state:-absent}, not Running" >&2
            failed="$failed $vm"
        elif multipass exec "$vm" -- sudo -n true; then
            info "$vm: multipass exec and sudo work"
        else
            echo "lab.sh: $vm: 'multipass exec $vm -- sudo -n true' failed" >&2
            failed="$failed $vm"
        fi
    done
    if [ -n "$failed" ]; then
        die "the multipass exec recovery path is broken on:$failed. Roll back with the last snapshot (ask first)."
    fi
}

valid_snapshot_name() {
    # Multipass applies instance-name rules: letters, digits, and hyphens,
    # starting with a letter and not ending with a hyphen.
    case "$1" in
        '' | [!A-Za-z]* | *[!A-Za-z0-9-]* | *-) return 1 ;;
    esac
    return 0
}

# Prints "vm snapshot" for every snapshot on the host. A listing that fails
# or reports errors stops the script: it must never read as "no snapshots".
snapshot_table() {
    local listing
    listing="$(multipass list --snapshots --format json)" || return 1
    printf '%s' "$listing" | "$PY" -c '
import json, sys
data = json.load(sys.stdin)
if data.get("errors") or not isinstance(data.get("info"), dict):
    sys.exit(1)
for vm, snapshots in data["info"].items():
    for name in snapshots:
        print(vm, name)
'
}

# What cmd_snapshot has done so far, for the cleanup on failure.
SNAPSHOT_NAME=""
SNAPSHOT_STOPPED=""
SNAPSHOT_TAKEN=""

snapshot_cleanup() {
    local vm
    for vm in $SNAPSHOT_STOPPED; do
        echo "lab.sh: snapshot failed; starting $vm again" >&2
        multipass start "$vm" || echo "lab.sh: could not start $vm. Run 'multipass start $vm'." >&2
    done
    if [ -n "$SNAPSHOT_TAKEN" ]; then
        echo "lab.sh: the set is incomplete. Snapshot '$SNAPSHOT_NAME' exists only on:$SNAPSHOT_TAKEN." >&2
        echo "lab.sh: use another name, or delete those snapshots first (multipass delete --purge <vm>.$SNAPSHOT_NAME; ask first)." >&2
    fi
}

# The snapshot is the real rollback (CLAUDE.md rule 4). Everything is checked
# before any VM is stopped: every lab VM exists, the snapshot listing works,
# and no VM has the name yet. If a step fails part way, stopped VMs are
# started again and the script says which VMs already got the snapshot.
cmd_snapshot() {
    local name="${1:-}" vms vm state snapshots
    valid_snapshot_name "$name" || die "usage: lab.sh snapshot <name> (letters, digits, hyphens; starts with a letter)"
    check_host
    require_venv
    require_multipass
    vms="$(lab_vms)"
    snapshots="$(snapshot_table)" || die "could not list snapshots ('multipass list --snapshots' failed or reported errors). Nothing was stopped."
    for vm in $vms; do
        state="$(vm_state "$vm")"
        case "$state" in
            Running | Stopped) ;;
            "") die "$vm does not exist. A snapshot of part of the lab is no rollback; run 'make lab-up' first." ;;
            *) die "$vm is in state '$state'; a snapshot needs it Running or Stopped" ;;
        esac
        if echo "$snapshots" | awk -v v="$vm" -v n="$name" '$1 == v && $2 == n {f = 1} END {exit !f}'; then
            die "$vm already has a snapshot named '$name'. Nothing was stopped. Pick another name."
        fi
    done
    SNAPSHOT_NAME="$name"
    trap snapshot_cleanup EXIT
    for vm in $vms; do
        state="$(vm_state "$vm")"
        if [ "$state" = Running ]; then
            info "stopping $vm (snapshots need a stopped VM)"
            SNAPSHOT_STOPPED="$SNAPSHOT_STOPPED $vm"
            multipass stop "$vm"
        fi
        info "taking snapshot $vm.$name"
        multipass snapshot --name "$name" "$vm"
        SNAPSHOT_TAKEN="$SNAPSHOT_TAKEN $vm"
        if [ "$state" = Running ]; then
            multipass start "$vm"
            SNAPSHOT_STOPPED="${SNAPSHOT_STOPPED% "$vm"}"
        fi
    done
    trap - EXIT
    info "snapshot '$name' taken on: $vms"
    info "to roll back: multipass restore --destructive <vm>.$name (discards the current state; ask first)"
}

case "${1:-}" in
    up) cmd_up ;;
    down) cmd_down ;;
    status) cmd_status ;;
    check) cmd_check ;;
    snapshot)
        shift
        cmd_snapshot "$@"
        ;;
    *) usage ;;
esac
