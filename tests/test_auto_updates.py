"""State tests for roles/auto_updates on the node and the monitor (F-25). They
need the lab: run `make verify`, or `pytest -m lab tests/test_auto_updates.py`
with .venv/bin on PATH.
"""

import re

import lab_hosts
import pytest

pytestmark = pytest.mark.lab
testinfra_hosts = lab_hosts.hosts("node", "monitor")

# What unattended-upgrade itself says it will use, after it expands
# ${distro_id} and ${distro_codename}. The release pocket is frozen at
# release; it is there so a security fix can pull in a new dependency.
ORIGINS = [
    "o=Ubuntu,a=noble",
    "o=Ubuntu,a=noble-security",
    "o=UbuntuESMApps,a=noble-apps-security",
    "o=UbuntuESM,a=noble-infra-security",
]


def apt_config(host) -> dict[str, list[str]]:
    """`apt-config dump` as key -> values (list keys repeat with `::`)."""
    values: dict[str, list[str]] = {}
    for line in host.check_output("apt-config dump").splitlines():
        match = re.fullmatch(r'(\S+?)(?:::)? "(.*)";', line)
        if match:
            values.setdefault(match.group(1), []).append(match.group(2))
    return values


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("APT::Periodic::Update-Package-Lists", "1"),
        ("APT::Periodic::Unattended-Upgrade", "1"),
        ("APT::Periodic::AutocleanInterval", "7"),
        ("Unattended-Upgrade::Automatic-Reboot", "false"),
        ("Unattended-Upgrade::Remove-Unused-Kernel-Packages", "true"),
    ],
)
def test_apt_config_shows_the_setting(host, key: str, value: str) -> None:
    assert apt_config(host).get(key) == [value]


def test_mail_follows_group_vars(host) -> None:
    mail = host.ansible.get_variables().get("auto_updates_mail", "")
    assert apt_config(host).get("Unattended-Upgrade::Mail") == [mail]


def test_only_security_origins_are_configured(host) -> None:
    origins = apt_config(host)["Unattended-Upgrade::Allowed-Origins"]
    # The first value is the list's own empty header line.
    assert [o for o in origins if o] == [
        "${distro_id}:${distro_codename}",
        "${distro_id}:${distro_codename}-security",
        "${distro_id}ESMApps:${distro_codename}-apps-security",
        "${distro_id}ESM:${distro_codename}-infra-security",
    ]
    assert "Unattended-Upgrade::Origins-Pattern" not in apt_config(host)


@pytest.mark.changes_state
def test_unattended_upgrade_uses_only_security_origins(host) -> None:
    # A dry run reads the same configuration the timer run will. No packages
    # are changed, but it writes its log and takes the apt lock.
    with host.sudo():
        out = host.check_output("unattended-upgrade --dry-run --debug 2>&1")
    line = re.search(r"^Allowed origins are: (.*)$", out, re.MULTILINE)
    assert line, out
    assert line.group(1).split(", ") == ORIGINS


@pytest.mark.parametrize("timer", ["apt-daily.timer", "apt-daily-upgrade.timer"])
def test_apt_timers_run(host, timer: str) -> None:
    assert host.service(timer).is_enabled
    assert host.run(f"systemctl is-active {timer}").stdout.strip() == "active"


def test_shutdown_waits_for_a_running_upgrade(host) -> None:
    # unattended-upgrades.service holds shutdown until an upgrade finishes,
    # so a reboot never leaves dpkg half done.
    assert host.service("unattended-upgrades").is_enabled
    assert host.run("systemctl is-active unattended-upgrades").stdout.strip() == "active"
