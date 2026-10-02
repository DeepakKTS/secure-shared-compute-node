"""State tests for roles/base on every lab VM (F-20). They need the lab:
run `make verify`, or `pytest -m lab tests/test_base.py` with .venv/bin on PATH.

Expected values come from the role defaults and inventory/group_vars, so the
tests prove the configuration is live, not just declared.
"""

import re
from pathlib import Path

import lab_hosts
import pytest
import yaml

pytestmark = pytest.mark.lab
testinfra_hosts = lab_hosts.hosts("all")

ROOT = Path(__file__).resolve().parent.parent
DEFAULTS = yaml.safe_load((ROOT / "roles" / "base" / "defaults" / "main.yml").read_text())
GROUP_VARS = yaml.safe_load((ROOT / "inventory" / "group_vars" / "all.yml").read_text())


def setting(name: str):
    return GROUP_VARS.get(name, DEFAULTS[name])


def sysctl(host, key: str):
    # Some keys (net.core.bpf_jit_harden) are readable only by root.
    with host.sudo():
        return host.sysctl(key)


@pytest.mark.parametrize("key", sorted(DEFAULTS["base_sysctl"]))
def test_sysctl_value_is_live(host, key: str) -> None:
    assert sysctl(host, key) == DEFAULTS["base_sysctl"][key]


def test_values_named_in_f20(host) -> None:
    # Checked by name, so a later change to the defaults cannot drop them.
    assert sysctl(host, "kernel.kptr_restrict") == 2
    assert sysctl(host, "fs.suid_dumpable") == 0


def test_rp_filter_holds_on_the_real_interface(host) -> None:
    # The kernel uses the larger of "all" and the interface value.
    want = setting("base_rp_filter")
    route = host.check_output("ip -4 route show default")
    device = re.search(r"\bdev (\S+)", route).group(1)
    for scope in ("all", "default", device):
        assert sysctl(host, f"net.ipv4.conf.{scope}.rp_filter") == want, scope


def test_forwarding_is_pinned_before_the_redirect_settings(host) -> None:
    # The kernel default is 0, so the live value is 0 without the pin. Read
    # the file: both keys are set, ahead of the redirect settings that a
    # change of net.ipv4.ip_forward resets.
    text = host.file("/etc/sysctl.d/99-zz-ssc-hardening.conf").content_string
    keys = [line.split(" = ")[0] for line in text.splitlines() if " = " in line]
    for key in ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"):
        assert f"{key} = 0" in text.splitlines(), key
        first_redirect = min(i for i, k in enumerate(keys) if "redirects" in k)
        assert keys.index(key) < first_redirect, keys


def test_hardening_file_applies_last(host) -> None:
    # A vendor file sorting after ours would undo values on every boot.
    with host.sudo():
        config = host.check_output("/usr/lib/systemd/systemd-sysctl --cat-config")
    files = re.findall(r"^# (/\S+\.conf)$", config, re.M)
    assert files[-1] == "/etc/sysctl.d/99-zz-ssc-hardening.conf", files


def test_chrony_replaces_timesyncd(host) -> None:
    chrony = host.service("chrony")
    assert chrony.is_running
    assert chrony.is_enabled
    assert not host.service("systemd-timesyncd").is_running


def test_chrony_parsed_config_has_the_lab_makestep(host) -> None:
    # chronyd -p prints the config as chronyd reads it, includes and all.
    with host.sudo():
        config = host.check_output("chronyd -p")
    steps = [line for line in config.splitlines() if line.startswith("makestep")]
    assert steps == [f"makestep {setting('base_chrony_makestep')}"]


def test_chrony_is_synchronised(host) -> None:
    tracking = host.check_output("chronyc -n tracking")
    assert re.search(r"^Leap status\s*:\s*Normal$", tracking, re.M), tracking


def test_timezone(host) -> None:
    assert host.check_output("timedatectl show -p Timezone --value") == setting("base_timezone")


@pytest.mark.parametrize("unit", DEFAULTS["base_apport_units"])
def test_apport_unit_is_masked_and_stopped(host, unit: str) -> None:
    assert host.run(f"systemctl is-enabled {unit}").stdout.strip() == "masked"
    assert host.run(f"systemctl is-active {unit}").stdout.strip() != "active"


def test_apport_is_off_in_its_config(host) -> None:
    assert host.file("/etc/default/apport").contains("^enabled=0$")


def test_core_pattern_does_not_pipe_to_apport(host) -> None:
    pattern = sysctl(host, "kernel.core_pattern")
    assert pattern == "core", pattern
    assert not str(pattern).startswith("|")


def test_core_dumps_are_limited_for_login_sessions(host) -> None:
    # testinfra's SSH session goes through pam_limits like any login.
    assert host.check_output("ulimit -Hc; ulimit -Sc").split() == ["0", "0"]


def test_core_dumps_are_limited_for_services(host) -> None:
    assert host.check_output("systemctl show -p DefaultLimitCORE --value") == "0"
    # A running service, not just the default: holds only after a reboot,
    # because services started before the change keep their old limit.
    pid = host.check_output("systemctl show -p MainPID --value cron")
    with host.sudo():
        limits = host.check_output(f"cat /proc/{pid}/limits")
    core = re.search(r"^Max core file size\s+(\S+)\s+(\S+)", limits, re.M)
    assert core.groups() == ("0", "0"), limits


def test_needrestart_restarts_without_asking(host) -> None:
    # needrestart cannot print its effective config, so read its conf.d file.
    conf = host.file("/etc/needrestart/conf.d/50-ssc.conf")
    assert conf.user == "root"
    assert conf.contains("nrconf{restart} = 'a';")
