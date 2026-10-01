"""State tests for roles/ssh_hardening on the node and the monitor (F-22).
They need the lab: run `make verify`, or `pytest -m lab tests/test_ssh_hardening.py`
with .venv/bin on PATH.
"""

import subprocess
from pathlib import Path

import lab_hosts
import pytest
import testinfra

pytestmark = pytest.mark.lab
testinfra_hosts = lab_hosts.hosts("node", "monitor")

LAB = Path(__file__).resolve().parent.parent / ".lab"

# F-22, as `sshd -T` prints it (keywords in lower case).
F22 = {
    "passwordauthentication": "no",
    "kbdinteractiveauthentication": "no",
    "permitrootlogin": "no",
    "pubkeyauthentication": "yes",
    "allowgroups": "sudo ssc-users",
    "maxauthtries": "3",
    "logingracetime": "30",
    "x11forwarding": "no",
    "allowagentforwarding": "no",
    "clientaliveinterval": "300",
}


def effective(host) -> dict[str, str]:
    """What sshd is using, from `sshd -T`, not what the file says."""
    with host.sudo():
        dump = host.check_output("sshd -T")
    values: dict[str, list[str]] = {}
    for line in dump.splitlines():
        key, _, value = line.partition(" ")
        values.setdefault(key, []).append(value)
    return {key: " ".join(found) for key, found in values.items()}


def name(host) -> str:
    return host.ansible.get_variables()["inventory_hostname"]


@pytest.mark.parametrize("key", sorted(F22))
def test_sshd_uses_the_f22_setting(host, key: str) -> None:
    assert effective(host).get(key) == F22[key]


def test_hardening_drop_in_is_read_first(host) -> None:
    files = host.check_output("ls -1 /etc/ssh/sshd_config.d/").split()
    assert [f for f in files if f.endswith(".conf")][0] == "00-hardening.conf", files


def test_full_sshd_config_is_valid(host) -> None:
    with host.sudo():
        assert host.run("sshd -t").rc == 0


@pytest.mark.usefixtures("attacker_unbanned")
@pytest.mark.parametrize("user", ["alice", "root"])
def test_password_login_from_the_attacker_is_refused(host, user: str) -> None:
    # The server must offer no password method at all, so the refusal lists
    # only "publickey". Host key checks are off on the attacker side only.
    # testinfra's ssh backend takes exit code 255 as "could not reach the
    # attacker" and raises, so the inner ssh's code is printed instead.
    target = host.ansible.get_variables()["ansible_host"]
    attacker = testinfra.get_host("ansible://ssc-attacker")
    result = attacker.run(
        "ssh -o BatchMode=yes -o ConnectTimeout=10 -o PubkeyAuthentication=no "
        "-o PreferredAuthentications=password,keyboard-interactive "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"{user}@{target} true 2>&1; echo inner_rc=$?"
    )
    assert result.rc == 0
    assert "inner_rc=255" in result.stdout, result.stdout
    assert "Permission denied (publickey)" in result.stdout, result.stdout


def test_new_admin_connection_works(host) -> None:
    # ControlPath=none: a fresh login, not a reused connection (rule 4).
    result = subprocess.run(
        ["ssh", "-F", str(LAB / "ssh_config"), "-o", "ControlPath=none", "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10", name(host), "sudo -n true"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr


def test_multipass_exec_still_works(host) -> None:
    # multipass exec logs in over sshd as ubuntu; it is the repair path.
    result = subprocess.run(
        ["multipass", "exec", name(host), "--", "sudo", "-n", "true"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
