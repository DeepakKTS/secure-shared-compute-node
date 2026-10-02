"""Unit tests for scripts/gen_inventory.py. No VMs: fixtures stand in for
`multipass list --format json`, and a fake runner stands in for `multipass exec`."""

import json
import stat
import subprocess
import sys
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

import gen_inventory as gi
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
FULL = (FIXTURES / "multipass_list_full.json").read_text()
SMALL = (FIXTURES / "multipass_list_small.json").read_text()
CONTROLLER = IPv4Address("192.168.64.1")
NET = IPv4Network("192.168.64.0/24")

# macOS `ifconfig` and Linux `ip -4 -o addr show`, trimmed.
IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:22:fb:00:00:01
\tinet 10.110.5.7 netmask 0xffff0000 broadcast 10.110.255.255
bridge100: flags=8a63<UP,BROADCAST,SMART,RUNNING,ALLMULTI,SIMPLEX,MULTICAST> mtu 1500
\toptions=3<RXCSUM,TXCSUM>
\tinet 192.168.64.1 netmask 0xffffff00 broadcast 192.168.64.255
\tinet6 fe80::1%bridge100 prefixlen 64 scopeid 0x10
"""
IP_ADDR = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.110.5.7/16 brd 10.110.255.255 scope global eth0\\       valid_lft forever
4: mpqemubr0  inet 192.168.64.1/24 brd 192.168.64.255 scope global mpqemubr0\\    valid_lft forever
"""
INTERFACES = gi.parse_ifconfig(IFCONFIG)


def fake_host(cmd: list[str]) -> str:
    """Runner that answers the host interface commands, as on a Multipass host."""
    if cmd == ["/sbin/ifconfig"]:
        return IFCONFIG
    if cmd[:2] == ["ip", "-4"]:
        return IP_ADDR
    raise AssertionError(f"unexpected command {cmd}")


def vm(name: str, state: str = "Running", ipv4: tuple[str, ...] = ("192.168.64.10",)) -> dict:
    return {"name": name, "state": state, "ipv4": list(ipv4), "release": "Ubuntu 24.04 LTS"}


def listing(*vms: dict) -> str:
    return json.dumps({"list": list(vms)})


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LAB_PROFILE", "LAB_CIDR", "LAB_CONTROLLER_IP"):
        monkeypatch.delenv(name, raising=False)


def test_full_profile_takes_lab_vms_only() -> None:
    assert gi.lab_vms(FULL, "full") == {
        "ssc-node": [IPv4Address("192.168.64.10")],
        "ssc-monitor": [IPv4Address("192.168.64.11"), IPv4Address("172.17.0.1")],
        "ssc-attacker": [IPv4Address("192.168.64.12")],
    }


def test_small_profile_needs_no_monitor_vm() -> None:
    assert set(gi.lab_vms(SMALL, "small")) == {"ssc-node", "ssc-attacker"}


def test_full_profile_fails_without_monitor() -> None:
    with pytest.raises(gi.InventoryError, match="ssc-monitor does not exist"):
        gi.lab_vms(SMALL, "full")


def test_unknown_profile_is_refused() -> None:
    with pytest.raises(gi.InventoryError, match="full or small"):
        gi.lab_vms(FULL, "tiny")


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (vm("ssc-node", state="Stopped"), "is Stopped"),
        (vm("ssc-node", ipv4=()), "no IPv4"),
        (vm("ssc-node", ipv4=("fd00::10",)), "no IPv4"),
    ],
)
def test_unusable_node_is_refused(node: dict, message: str) -> None:
    attacker = vm("ssc-attacker", ipv4=("192.168.64.12",))
    with pytest.raises(gi.InventoryError, match=message):
        gi.lab_vms(listing(node, attacker), "small")


def test_parse_ifconfig_reads_names_and_netmasks() -> None:
    assert [(n, str(i)) for n, i in INTERFACES] == [
        ("lo0", "127.0.0.1/8"),
        ("en0", "10.110.5.7/16"),
        ("bridge100", "192.168.64.1/24"),
    ]


def test_parse_ip_addr_reads_names_and_prefixes() -> None:
    assert [(n, str(i)) for n, i in gi.parse_ip_addr(IP_ADDR)] == [
        ("lo", "127.0.0.1/8"),
        ("eth0", "10.110.5.7/16"),
        ("mpqemubr0", "192.168.64.1/24"),
    ]


@pytest.mark.parametrize("system", ["Darwin", "Linux"])
def test_host_interfaces_finds_the_bridge_on_each_os(system: str) -> None:
    bridge, network = gi.lab_bridge(CONTROLLER, gi.host_interfaces(fake_host, system))
    assert bridge in ("bridge100", "mpqemubr0")
    assert network == NET


def test_host_interfaces_refuses_other_systems() -> None:
    with pytest.raises(gi.InventoryError, match="unsupported host OS"):
        gi.host_interfaces(fake_host, "Windows")


def test_controller_on_a_lan_interface_is_refused() -> None:
    # A VM bridged onto a campus network: the controller reaches it from en0.
    with pytest.raises(gi.InventoryError, match="on en0, not on a Multipass bridge"):
        gi.lab_bridge(IPv4Address("10.110.5.7"), INTERFACES)


def test_controller_that_is_not_a_host_address_is_refused() -> None:
    with pytest.raises(gi.InventoryError, match="not an address of this host"):
        gi.lab_bridge(IPv4Address("192.168.64.99"), INTERFACES)


def test_network_is_the_bridge_network() -> None:
    assert gi.lab_network(CONTROLLER, NET) == NET


def test_wide_bridge_is_narrowed_to_a_slash_24() -> None:
    wide = IPv4Network("192.168.0.0/16")
    assert gi.lab_network(IPv4Address("192.168.64.1"), wide) == NET


def test_override_may_narrow_the_network() -> None:
    narrow = gi.lab_network(CONTROLLER, NET, "192.168.64.0/26")
    assert narrow == IPv4Network("192.168.64.0/26")


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ("10.0.0.0/8", "wider than /24"),
        ("192.168.64.0/23", "wider than /24"),
        ("192.168.65.0/24", "not inside the bridge"),
        ("192.168.64.128/25", "controller IP 192.168.64.1 is not inside"),
    ],
)
def test_bad_override_is_refused(override: str, message: str) -> None:
    with pytest.raises(gi.InventoryError, match=message):
        gi.lab_network(CONTROLLER, NET, override)


@pytest.mark.parametrize("network", ["127.0.0.0/24", "169.254.1.0/24", "198.18.0.0/24"])
def test_non_rfc1918_network_is_refused(network: str) -> None:
    # ipaddress.is_private is true for all of these; none is a lab network.
    bridge = IPv4Network(network)
    controller = next(bridge.hosts())
    with pytest.raises(gi.InventoryError, match="RFC 1918"):
        gi.lab_network(controller, bridge)


def test_each_vm_uses_its_address_on_the_lab_network() -> None:
    # The monitor also has docker0 (172.17.0.1); a docker-first order must not matter.
    vms = gi.lab_vms(
        listing(
            vm("ssc-node", ipv4=("172.17.0.1", "192.168.64.10")),
            vm("ssc-monitor", ipv4=("192.168.64.11", "172.17.0.1")),
            vm("ssc-attacker", ipv4=("192.168.64.12",)),
        ),
        "full",
    )
    assert gi.lab_hosts(vms, NET) == {
        "ssc-node": IPv4Address("192.168.64.10"),
        "ssc-monitor": IPv4Address("192.168.64.11"),
        "ssc-attacker": IPv4Address("192.168.64.12"),
    }


def test_vm_with_no_address_on_the_lab_network_is_refused() -> None:
    # Bridged onto a campus network only: private, but not lab.
    vms = gi.lab_vms(listing(vm("ssc-node"), vm("ssc-attacker", ipv4=("10.110.5.20",))), "small")
    with pytest.raises(gi.InventoryError, match="ssc-attacker has no address inside"):
        gi.lab_hosts(vms, NET)


def test_parse_ssh_connection() -> None:
    assert gi.parse_ssh_connection("192.168.64.1 51234 192.168.64.10 22\n") == CONTROLLER
    assert gi.parse_ssh_connection("\n") is None
    assert gi.parse_ssh_connection("not an address 1 2") is None


def test_parse_default_route() -> None:
    route = "default via 192.168.64.1 dev enp0s1 proto dhcp src 192.168.64.10 metric 100\n"
    assert gi.parse_default_route(route) == CONTROLLER
    assert gi.parse_default_route("") is None
    assert gi.parse_default_route("default via") is None


def test_detect_controller_prefers_the_multipass_ssh_session() -> None:
    calls: list[list[str]] = []

    def run(cmd: list[str]) -> str:
        calls.append(cmd)
        return "192.168.64.1 50000 192.168.64.10 22\n"

    address, how = gi.detect_controller_ip(run)
    assert address == CONTROLLER
    assert "SSH_CONNECTION" in how
    assert len(calls) == 1
    assert calls[0][:4] == ["multipass", "exec", "ssc-node", "--"]


def test_detect_controller_falls_back_to_the_gateway() -> None:
    outputs = iter(["\n", "default via 192.168.64.1 dev enp0s1 proto dhcp\n"])
    address, how = gi.detect_controller_ip(lambda cmd: next(outputs))
    assert address == CONTROLLER
    assert "gateway" in how


def test_detect_controller_fails_closed() -> None:
    with pytest.raises(gi.InventoryError, match="LAB_CONTROLLER_IP"):
        gi.detect_controller_ip(lambda cmd: "")


def test_inventory_vars_and_groups(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    hosts = gi.lab_hosts(gi.lab_vms(FULL, "full"), NET)
    inventory = gi.build_inventory(hosts, "full", NET, CONTROLLER, "ssc-admin", tmp_path)
    variables = inventory["all"]["vars"]
    assert variables["ansible_user"] == "ssc-admin"
    key = Path(variables["ansible_ssh_private_key_file"])
    assert key.is_absolute()
    # The key lives outside the repo (scripts/lab.sh KEY_DIR).
    assert key == tmp_path / "home" / ".config" / "ssc-lab" / "keys" / "ssc_admin_ed25519"
    ssh_args = variables["ansible_ssh_common_args"]
    assert "-o IdentitiesOnly=yes" in ssh_args
    assert f"-o UserKnownHostsFile={tmp_path / '.lab' / 'known_hosts'}" in ssh_args
    assert "-o StrictHostKeyChecking=accept-new" in ssh_args
    assert variables["ansible_python_interpreter"] == "/usr/bin/python3"
    assert variables["lab_cidr"] == "192.168.64.0/24"
    assert variables["lab_controller_ip"] == "192.168.64.1"
    groups = {g: list(c["hosts"]) for g, c in inventory["all"]["children"].items()}
    assert groups == {
        "node": ["ssc-node"],
        "monitor": ["ssc-monitor"],
        "attacker": ["ssc-attacker"],
    }


def test_small_profile_puts_the_node_in_the_monitor_group(tmp_path: Path) -> None:
    hosts = gi.lab_hosts(gi.lab_vms(SMALL, "small"), NET)
    inventory = gi.build_inventory(hosts, "small", NET, CONTROLLER, "ssc-admin", tmp_path)
    groups = {g: list(c["hosts"]) for g, c in inventory["all"]["children"].items()}
    assert groups == {"node": ["ssc-node"], "monitor": ["ssc-node"], "attacker": ["ssc-attacker"]}
    assert inventory["all"]["vars"]["lab_profile"] == "small"


@pytest.mark.parametrize(
    ("controller", "message"),
    [("10.0.0.1", "not inside"), ("192.168.64.10", "is a lab VM address")],
)
def test_bad_controller_ip_is_refused(tmp_path: Path, controller: str, message: str) -> None:
    hosts = gi.lab_hosts(gi.lab_vms(FULL, "full"), NET)
    with pytest.raises(gi.InventoryError, match=message):
        gi.build_inventory(hosts, "full", NET, IPv4Address(controller), "ssc-admin", tmp_path)


def test_ssh_config_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    text = gi.render_ssh_config(gi.lab_hosts(gi.lab_vms(FULL, "full"), NET), "ssc-admin", tmp_path)
    assert "Host ssc-node\n  HostName 192.168.64.10\n  User ssc-admin\n" in text
    key = tmp_path / "home" / ".config" / "ssc-lab" / "keys" / "ssc_admin_ed25519"
    assert f'IdentityFile "{key}"' in text
    assert text.count("IdentitiesOnly yes") == 3
    assert "StrictHostKeyChecking no" not in text


def run_cli(
    tmp_path: Path, fixture: str = "multipass_list_full.json", controller: str = "192.168.64.1"
) -> int:
    return gi.main(
        [
            "--multipass-json",
            str(FIXTURES / fixture),
            "--controller-ip",
            controller,
            "--root",
            str(tmp_path),
        ],
        run=fake_host,
    )


def test_cli_writes_files_that_ansible_parses(tmp_path: Path) -> None:
    assert run_cli(tmp_path) == 0
    inventory = tmp_path / "inventory" / "lab.yml"
    assert inventory.read_text().startswith("# Generated by scripts/gen_inventory.py")
    ssh_config = tmp_path / ".lab" / "ssh_config"
    assert stat.S_IMODE(ssh_config.stat().st_mode) == 0o600
    ansible_inventory = Path(sys.executable).parent / "ansible-inventory"
    result = subprocess.run(
        [str(ansible_inventory), "-i", str(inventory), "--list"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(result.stdout)
    hostvars = data["_meta"]["hostvars"]
    assert set(hostvars) == {"ssc-node", "ssc-monitor", "ssc-attacker"}
    assert hostvars["ssc-node"]["ansible_host"] == "192.168.64.10"
    assert data["node"]["hosts"] == ["ssc-node"]


def test_cli_output_is_stable(tmp_path: Path) -> None:
    assert run_cli(tmp_path) == 0
    first = (tmp_path / "inventory" / "lab.yml").read_text()
    assert run_cli(tmp_path) == 0
    assert (tmp_path / "inventory" / "lab.yml").read_text() == first


def test_cli_fails_closed_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_cli(tmp_path, "multipass_list_small.json") == 1
    assert "ssc-monitor does not exist" in capsys.readouterr().err
    assert run_cli(tmp_path, controller="10.110.5.7") == 1
    assert "not on a Multipass bridge" in capsys.readouterr().err
    assert not (tmp_path / "inventory" / "lab.yml").exists()


def test_cli_lab_cidr_wider_than_slash_24_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LAB_CIDR", "192.168.0.0/16")
    assert run_cli(tmp_path) == 1
    assert "wider than /24" in capsys.readouterr().err
    assert not (tmp_path / "inventory" / "lab.yml").exists()


def test_example_inventory_has_the_same_vars_as_generated(tmp_path: Path) -> None:
    hosts = gi.lab_hosts(gi.lab_vms(FULL, "full"), NET)
    generated = gi.build_inventory(hosts, "full", NET, CONTROLLER, "ssc-admin", tmp_path)
    example = yaml.safe_load((ROOT / "inventory" / "lab.yml.example").read_text())
    assert set(example["all"]["vars"]) == set(generated["all"]["vars"])
    assert set(example["all"]["children"]) == set(generated["all"]["children"])
