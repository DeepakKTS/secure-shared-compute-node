"""State tests for roles/users on the node and the monitor (F-21). They need
the lab: run `make verify`, or `pytest -m lab tests/test_users.py` with
.venv/bin on PATH. Expected users come from each host's inventory variables.
"""

import subprocess
from pathlib import Path

import lab_hosts
import pytest

pytestmark = pytest.mark.lab
testinfra_hosts = lab_hosts.hosts("node", "monitor")

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / ".lab"


def variables(host) -> dict:
    return host.ansible.get_variables()


def research_users(host) -> list[dict]:
    return variables(host).get("users_research", [])


def test_research_users_have_no_sudo(host) -> None:
    for user in research_users(host):
        with host.sudo():
            listing = host.check_output(f"sudo -l -U {user['name']}")
        assert "is not allowed to run sudo" in listing, listing


def test_research_users_only_extra_group_is_ssc_users(host) -> None:
    for user in research_users(host):
        assert sorted(host.user(user["name"]).groups) == sorted([user["name"], "ssc-users"])


def test_ssc_users_has_exactly_the_research_users(host) -> None:
    # Empty on the monitor: no research user can log in there.
    members = host.check_output("getent group ssc-users").split(":")[3]
    assert {m for m in members.split(",") if m} == {u["name"] for u in research_users(host)}


def test_research_homes_are_private(host) -> None:
    for user in research_users(host):
        home = host.file(f"/home/{user['name']}")
        assert home.user == user["name"]
        assert home.mode == 0o700


def test_research_user_logs_in_with_its_key(host) -> None:
    address = variables(host)["ansible_host"]
    for user in research_users(host):
        if "ssh_public_key" in user:
            continue  # a real user's key; the lab holds no private half
        # Research user keys sit next to the admin key, outside the repo.
        key_dir = Path(variables(host)["ansible_ssh_private_key_file"]).parent
        key = key_dir / f"{user['name']}_ed25519"
        result = subprocess.run(
            [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "ControlPath=none",
                "-o", "IdentitiesOnly=yes",
                "-o", f"UserKnownHostsFile={LAB / 'known_hosts'}",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=10",
                "-i", str(key),
                f"{user['name']}@{address}",
                "id -un",
            ],
            capture_output=True,
            text=True,
            check=False,
        )  # fmt: skip
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == user["name"]


@pytest.mark.parametrize("account", ["admin", "ubuntu"])
def test_admin_and_ubuntu_keep_passwordless_sudo(host, account: str) -> None:
    name = variables(host)["admin_user"] if account == "admin" else "ubuntu"
    assert "sudo" in host.user(name).groups
    with host.sudo():
        listing = host.check_output(f"sudo -l -U {name}")
    assert "(ALL) NOPASSWD: ALL" in listing, listing


def test_sudo_policy_is_valid_and_managed(host) -> None:
    with host.sudo():
        assert host.run("visudo -c").rc == 0
        policy = host.file("/etc/sudoers.d/90-cloud-init-users")
        assert policy.mode == 0o440
        assert policy.contains("Managed by Ansible (role: users)")
