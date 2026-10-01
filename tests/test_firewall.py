"""State tests for roles/firewall on the node and the monitor (F-23). They need
the lab: run `make verify`, or `pytest -m lab tests/test_firewall.py` with
.venv/bin on PATH. Probes run from ssc-attacker, a lab host in the inventory.
"""

import re
import subprocess
from pathlib import Path

import lab_hosts
import pytest
import testinfra

pytestmark = pytest.mark.lab
testinfra_hosts = lab_hosts.hosts("node", "monitor")

LAB = Path(__file__).resolve().parent.parent / ".lab"
OPEN, REFUSED, TIMED_OUT = 0, 1, 124


def variables(host) -> dict:
    return host.ansible.get_variables()


def input_chain(host) -> str:
    with host.sudo():
        return host.check_output("nft list chain inet ssc_filter input")


def attacker():
    return testinfra.get_host("ansible://ssc-attacker")


def probe(target: str, port: int) -> int:
    """TCP connect from the attacker: 0 open, 1 refused, 124 timed out (dropped)."""
    result = attacker().run(
        f"timeout 3 bash -c 'echo > /dev/tcp/{target}/{port}' 2>/dev/null; echo rc=$?"
    )
    return int(re.search(r"rc=(\d+)", result.stdout).group(1))


def test_nftables_loads_at_boot(host) -> None:
    assert host.service("nftables").is_enabled
    assert host.run("systemctl is-active nftables").stdout.strip() == "active"


def test_ufw_is_off(host) -> None:
    assert host.run("systemctl is-enabled ufw").stdout.strip() == "masked"
    assert host.file("/etc/ufw/ufw.conf").contains("^ENABLED=no$")


def test_input_policy_is_drop(host) -> None:
    assert "type filter hook input priority filter; policy drop;" in input_chain(host)


def test_ssh_is_allowed_from_admin_sources_controller_first(host) -> None:
    chain = input_chain(host)
    v = variables(host)
    controller = f'ip saddr {v["lab_controller_ip"]} tcp dport 22 accept comment "controller"'
    lab = f'ip saddr {v["lab_cidr"]} tcp dport 22 accept comment "lab_cidr"'
    assert controller in chain and lab in chain, chain
    assert chain.index(controller) < chain.index(lab)
    for cidr in v.get("firewall_admin_cidrs", []):
        assert f"ip saddr {cidr} tcp dport 22 accept" in chain


def test_replies_dhcp_and_neighbour_discovery_are_allowed(host) -> None:
    chain = input_chain(host)
    for rule in (
        'iif "lo" accept',
        "ct state established,related accept",
        "ct state invalid drop",
        'udp sport 67 udp dport 68 accept comment "dhcpv4"',
        "nd-neighbor-solicit",
    ):
        assert rule in chain, rule


@pytest.mark.changes_state
@pytest.mark.usefixtures("attacker_unbanned")
def test_scan_from_the_attacker_finds_only_ssh(host) -> None:
    target = variables(host)["ansible_host"]
    scan = attacker().run(
        "seq 1 1024 | xargs -P 128 -I PORT timeout 3 bash -c "
        f"'echo > /dev/tcp/{target}/PORT && echo open:PORT' 2>/dev/null; true"
    )
    assert sorted(scan.stdout.split()) == ["open:22"], scan.stdout


@pytest.mark.parametrize("port", [23, 80, 443, 3306, 8080])
def test_closed_port_is_dropped_not_refused(host, port: int) -> None:
    # With no firewall a closed port answers with a reset at once (refused).
    # Dropped, it times out, and a scan learns nothing.
    assert probe(variables(host)["ansible_host"], port) == TIMED_OUT


@pytest.mark.changes_state
def test_new_listener_is_local_only(host) -> None:
    # A bare socket under a throwaway user: it serves nothing, even if the
    # firewall were open.
    listener = (
        "import socket, time; s = socket.socket(); "
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
        "s.bind(('0.0.0.0', 8888)); s.listen(); time.sleep(120)"
    )
    with host.sudo():
        host.run("systemctl stop ssc-fw-probe")
        host.check_output(
            "systemd-run --unit=ssc-fw-probe -p DynamicUser=yes -p RuntimeMaxSec=120 "
            f'/usr/bin/python3 -c "{listener}"'
        )
    try:
        ready = host.run(
            "for i in $(seq 1 20); do ss -tlnH | grep -q ':8888 ' && exit 0; sleep 0.5; done;"
            " exit 1"
        )
        assert ready.rc == 0, "listener did not start"
        assert host.run("timeout 3 bash -c 'echo > /dev/tcp/127.0.0.1/8888'").rc == OPEN
        assert probe(variables(host)["ansible_host"], 8888) == TIMED_OUT
    finally:
        with host.sudo():
            host.run("systemctl stop ssc-fw-probe")


def test_new_admin_connection_and_multipass_exec_work(host) -> None:
    name = variables(host)["inventory_hostname"]
    for cmd in (
        ["ssh", "-F", str(LAB / "ssh_config"), "-o", "ControlPath=none", "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10", name, "sudo -n true"],
        ["multipass", "exec", name, "--", "sudo", "-n", "true"],
    ):  # fmt: skip
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        assert result.returncode == 0, (cmd[0], result.stderr)
