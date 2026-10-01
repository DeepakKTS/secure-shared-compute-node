"""Unit tests for scripts/lab.sh, run against a fake multipass.

Each test copies lab.sh into a temp repo and runs it with PATH set to a fake
bin dir plus /usr/bin:/bin. A real Multipass install (/usr/local/bin on
macOS, /snap/bin on Linux) is never on PATH, so no real VM is touched.
On macOS this also runs the script under bash 3.2.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
GIB_KB = 1024 * 1024

FAKE_MULTIPASS = """#!{python}
import json, os, sys
state_path = os.environ["FAKE_MP_STATE"]
with open(os.environ["FAKE_MP_LOG"], "a") as log:
    log.write(" ".join(sys.argv[1:]) + "\\n")
try:
    with open(state_path) as f:
        vms = json.load(f)
except FileNotFoundError:
    vms = {{}}
args = sys.argv[1:]
cmd = args[0] if args else ""
names = [a for a in args[1:] if not a.startswith("-")]

def save():
    with open(state_path, "w") as f:
        json.dump(vms, f)

if cmd == "list":
    print(json.dumps({{"list": [
        {{"name": n, "state": v["state"], "ipv4": v["ipv4"], "release": "Ubuntu 24.04 LTS"}}
        for n, v in vms.items()
    ]}}))
elif cmd == "launch":
    name = args[args.index("--name") + 1]
    vms[name] = {{"state": "Running", "ipv4": ["192.168.64.%d" % (10 + len(vms))]}}
    save()
elif cmd in ("start", "stop"):
    for n in names:
        vms[n]["state"] = "Running" if cmd == "start" else "Stopped"
    save()
elif cmd == "delete":
    for n in names:
        vms.pop(n, None)
    save()
elif cmd == "snapshot":
    pass
elif cmd == "exec":
    # FAKE_MP_EXEC_FAIL lists VMs whose `multipass exec` fails.
    if args[1] in os.environ.get("FAKE_MP_EXEC_FAIL", "").split(","):
        sys.exit(1)
else:
    sys.exit("fake multipass: unsupported command " + cmd)
"""

FAKE_DF = """#!/bin/sh
echo "Filesystem 1024-blocks Used Available Capacity Mounted on"
echo "/dev/fake 999999999 1 ${FAKE_DF_KB} 1% /"
"""

FAKE_UNAME = """#!/bin/sh
case "$1" in -s) echo FreeBSD ;; -m) echo x86_64 ;; esac
"""


def write_exe(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class Lab:
    """A temp copy of the repo bits lab.sh needs, plus fake tools."""

    def __init__(self, tmp: Path) -> None:
        self.root = tmp / "repo"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "inventory").mkdir()
        (self.root / ".venv" / "bin").mkdir(parents=True)
        for name in ("lab.sh", "cloud-init.yaml.tmpl"):
            shutil.copy(ROOT / "scripts" / name, self.root / "scripts" / name)
        (self.root / ".venv" / "bin" / "python").symlink_to(sys.executable)
        self.bin = tmp / "fakebin"
        self.bin.mkdir()
        write_exe(self.bin / "multipass", FAKE_MULTIPASS.format(python=sys.executable))
        write_exe(self.bin / "df", FAKE_DF)
        self.state = tmp / "mp_state.json"
        self.log = tmp / "mp_log.txt"
        self.log.write_text("")
        self.env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(tmp),
            "FAKE_MP_STATE": str(self.state),
            "FAKE_MP_LOG": str(self.log),
            "FAKE_DF_KB": str(500 * GIB_KB),
        }

    def run(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", str(self.root / "scripts" / "lab.sh"), *args],
            env={**self.env, **env},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()

    def set_vms(self, vms: dict[str, str]) -> None:
        self.state.write_text(
            json.dumps(
                {
                    n: {"state": s, "ipv4": [f"192.168.64.{i + 10}"]}
                    for i, (n, s) in enumerate(vms.items())
                }
            )
        )


@pytest.fixture
def lab(tmp_path: Path) -> Lab:
    return Lab(tmp_path)


def launches(lab: Lab) -> list[str]:
    return [c for c in lab.calls() if c.startswith("launch ")]


def test_admin_user_matches_group_vars() -> None:
    group_vars = yaml.safe_load((ROOT / "inventory" / "group_vars" / "all.yml").read_text())
    assert f'ADMIN_USER="{group_vars["admin_user"]}"' in (ROOT / "scripts" / "lab.sh").read_text()


def test_up_creates_three_vms_with_documented_sizes(lab: Lab) -> None:
    result = lab.run("up")
    assert result.returncode == 0, result.stderr
    tail = f"--cloud-init {lab.root / '.lab' / 'cloud-init.yaml'} --timeout 900"
    assert launches(lab) == [
        f"launch 24.04 --name ssc-node --cpus 2 --memory 2G --disk 15G {tail}",
        f"launch 24.04 --name ssc-monitor --cpus 2 --memory 2G --disk 10G {tail}",
        f"launch 24.04 --name ssc-attacker --cpus 1 --memory 1G --disk 5G {tail}",
    ]


def test_up_generates_private_key_and_renders_cloud_init(lab: Lab) -> None:
    assert lab.run("up").returncode == 0
    key = lab.root / ".lab" / "keys" / "ssc_admin_ed25519"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE((lab.root / ".lab").stat().st_mode) == 0o700
    rendered = (lab.root / ".lab" / "cloud-init.yaml").read_text()
    assert rendered.startswith("#cloud-config\n")
    assert stat.S_IMODE((lab.root / ".lab" / "cloud-init.yaml").stat().st_mode) == 0o600
    users = yaml.safe_load(rendered)["users"]
    assert users[0] == "default", "the ubuntu user must stay for multipass exec"
    admin = users[1]
    assert admin["name"] == "ssc-admin"
    assert admin["groups"] == ["sudo"]
    assert admin["lock_passwd"] is True
    assert admin["ssh_authorized_keys"] == [Path(f"{key}.pub").read_text().strip()]


def test_up_is_idempotent_and_keeps_the_key(lab: Lab) -> None:
    assert lab.run("up").returncode == 0
    key = lab.root / ".lab" / "keys" / "ssc_admin_ed25519"
    first_key = key.read_text()
    assert lab.run("up").returncode == 0
    assert len(launches(lab)) == 3
    assert key.read_text() == first_key


def test_up_starts_a_stopped_vm(lab: Lab) -> None:
    lab.set_vms({"ssc-node": "Running", "ssc-monitor": "Stopped", "ssc-attacker": "Running"})
    assert lab.run("up").returncode == 0
    assert "start ssc-monitor" in lab.calls()
    assert launches(lab) == []


def test_up_refuses_a_deleted_but_unpurged_vm(lab: Lab) -> None:
    lab.set_vms({"ssc-node": "Deleted"})
    result = lab.run("up")
    assert result.returncode != 0
    assert "multipass recover ssc-node" in result.stderr
    assert launches(lab) == []


def test_small_profile_skips_the_monitor(lab: Lab) -> None:
    assert lab.run("up", LAB_PROFILE="small").returncode == 0
    names = [c.split("--name ")[1].split()[0] for c in launches(lab)]
    assert names == ["ssc-node", "ssc-attacker"]


def test_unknown_profile_is_rejected(lab: Lab) -> None:
    result = lab.run("up", LAB_PROFILE="tiny")
    assert result.returncode != 0
    assert "LAB_PROFILE must be full or small" in result.stderr
    assert launches(lab) == []


def test_up_refuses_when_disk_is_short(lab: Lab) -> None:
    result = lab.run("up", FAKE_DF_KB=str(10 * GIB_KB))
    assert result.returncode != 0
    assert "not enough free disk" in result.stderr
    assert launches(lab) == []


def test_disk_check_counts_only_new_vms(lab: Lab) -> None:
    lab.set_vms({"ssc-node": "Running", "ssc-monitor": "Running"})
    # Only the attacker (5G) is new; 6G free is enough.
    assert lab.run("up", FAKE_DF_KB=str(6 * GIB_KB)).returncode == 0
    assert len(launches(lab)) == 1


def test_missing_multipass_gives_install_hint(lab: Lab) -> None:
    (lab.bin / "multipass").unlink()
    result = lab.run("up")
    assert result.returncode != 0
    assert "Multipass not found" in result.stderr


def test_missing_venv_says_run_make_deps(lab: Lab) -> None:
    (lab.root / ".venv" / "bin" / "python").unlink()
    result = lab.run("up")
    assert result.returncode != 0
    assert "make deps" in result.stderr


def test_unsupported_host_os_is_rejected(lab: Lab) -> None:
    write_exe(lab.bin / "uname", FAKE_UNAME)
    result = lab.run("up")
    assert result.returncode != 0
    assert "unsupported host OS 'FreeBSD'" in result.stderr


def test_down_without_confirmation_deletes_nothing(lab: Lab) -> None:
    lab.set_vms({"ssc-node": "Running", "ssc-monitor": "Running", "ssc-attacker": "Running"})
    result = lab.run("down")
    assert result.returncode != 0
    assert "CONFIRM=yes" in result.stderr
    assert lab.calls() == [], "down must not call multipass before it is confirmed"


def test_down_confirmed_deletes_only_lab_vms(lab: Lab) -> None:
    lab.set_vms({"ssc-node": "Running", "other-vm": "Running", "ssc-attacker": "Stopped"})
    lab_dir = lab.root / ".lab"
    (lab_dir / "keys").mkdir(parents=True)
    generated = [
        lab.root / "inventory" / "lab.yml",
        lab_dir / "known_hosts",
        lab_dir / "ssh_config",
    ]
    for path in [*generated, lab_dir / "keys" / "ssc_admin_ed25519"]:
        path.write_text("x")
    result = lab.run("down", CONFIRM="yes")
    assert result.returncode == 0, result.stderr
    assert "delete --purge ssc-node ssc-attacker" in lab.calls()
    assert not any(c.split()[0] == "purge" for c in lab.calls()), "never a bare multipass purge"
    assert "other-vm" in json.loads(lab.state.read_text())
    assert not any(p.exists() for p in generated)
    assert (lab_dir / "keys" / "ssc_admin_ed25519").exists(), "down keeps the keys"


def execs(lab: Lab) -> list[str]:
    return [c for c in lab.calls() if c.startswith("exec ")]


def test_check_runs_sudo_through_multipass_exec_on_each_vm(lab: Lab) -> None:
    lab.set_vms({"ssc-node": "Running", "ssc-monitor": "Running", "ssc-attacker": "Running"})
    result = lab.run("check")
    assert result.returncode == 0, result.stderr
    assert execs(lab) == [
        "exec ssc-node -- sudo -n true",
        "exec ssc-monitor -- sudo -n true",
        "exec ssc-attacker -- sudo -n true",
    ]


def test_check_fails_when_exec_fails_and_still_checks_the_rest(lab: Lab) -> None:
    lab.set_vms({"ssc-node": "Running", "ssc-monitor": "Running", "ssc-attacker": "Running"})
    result = lab.run("check", FAKE_MP_EXEC_FAIL="ssc-monitor")
    assert result.returncode != 0
    assert "recovery path is broken on: ssc-monitor" in result.stderr
    assert len(execs(lab)) == 3


def test_check_fails_for_a_missing_or_stopped_vm(lab: Lab) -> None:
    lab.set_vms({"ssc-node": "Stopped", "ssc-attacker": "Running"})
    result = lab.run("check")
    assert result.returncode != 0
    assert "ssc-node is Stopped" in result.stderr
    assert "ssc-monitor is absent" in result.stderr
    assert execs(lab) == ["exec ssc-attacker -- sudo -n true"]


def test_check_small_profile_skips_the_monitor(lab: Lab) -> None:
    lab.set_vms({"ssc-node": "Running", "ssc-attacker": "Running"})
    assert lab.run("check", LAB_PROFILE="small").returncode == 0
    assert [c.split()[1] for c in execs(lab)] == ["ssc-node", "ssc-attacker"]


def test_snapshot_stops_snapshots_and_restarts_running_vms(lab: Lab) -> None:
    lab.set_vms({"ssc-node": "Running", "ssc-monitor": "Stopped", "ssc-attacker": "Running"})
    assert lab.run("snapshot", "pre-harden").returncode == 0
    calls = [c for c in lab.calls() if not c.startswith("list ")]
    assert calls == [
        "stop ssc-node",
        "snapshot --name pre-harden ssc-node",
        "start ssc-node",
        "snapshot --name pre-harden ssc-monitor",
        "stop ssc-attacker",
        "snapshot --name pre-harden ssc-attacker",
        "start ssc-attacker",
    ]


@pytest.mark.parametrize("name", ["", "-x", "1abc", "a_b", "abc-", "a b"])
def test_snapshot_rejects_bad_names(lab: Lab, name: str) -> None:
    lab.set_vms({"ssc-node": "Running"})
    result = lab.run("snapshot", name)
    assert result.returncode != 0
    assert lab.calls() == []


def test_unknown_command_prints_usage(lab: Lab) -> None:
    result = lab.run("frobnicate")
    assert result.returncode == 2
    assert "usage:" in result.stderr


def test_status_without_multipass_still_reports_files(lab: Lab) -> None:
    (lab.bin / "multipass").unlink()
    result = lab.run("status")
    assert result.returncode == 0, result.stderr
    assert "multipass: not installed" in result.stdout
    assert "inventory/lab.yml: missing" in result.stdout


def test_lab_sh_is_executable() -> None:
    assert os.access(ROOT / "scripts" / "lab.sh", os.X_OK)
