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


def vm(name: str, state: str = "Running", ipv4: tuple[str, ...] = ("192.168.64.10",)) -> dict:
    return {"name": name, "state": state, "ipv4": list(ipv4), "release": "Ubuntu 24.04 LTS"}


def listing(*vms: dict) -> str:
    return json.dumps({"list": list(vms)})


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LAB_PROFILE", "LAB_CIDR", "LAB_CONTROLLER_IP"):
        monkeypatch.delenv(name, raising=False)


def test_full_profile_takes_lab_vms_only_and_first_ipv4() -> None:
    assert gi.lab_hosts(FULL, "full") == {
        "ssc-node": IPv4Address("192.168.64.10"),
        "ssc-monitor": IPv4Address("192.168.64.11"),
        "ssc-attacker": IPv4Address("192.168.64.12"),
    }


def test_small_profile_needs_no_monitor_vm() -> None:
    assert set(gi.lab_hosts(SMALL, "small")) == {"ssc-node", "ssc-attacker"}


def test_full_profile_fails_without_monitor() -> None:
    with pytest.raises(gi.InventoryError, match="ssc-monitor does not exist"):
        gi.lab_hosts(SMALL, "full")


def test_unknown_profile_is_refused() -> None:
    with pytest.raises(gi.InventoryError, match="full or small"):
        gi.lab_hosts(FULL, "tiny")


@pytest.mark.parametrize(
    ("node", "message"),
    [
        (vm("ssc-node", state="Stopped"), "is Stopped"),
        (vm("ssc-node", ipv4=()), "no IPv4"),
        (vm("ssc-node", ipv4=("8.8.8.8",)), "non-private"),
    ],
)
def test_unusable_node_is_refused(node: dict, message: str) -> None:
    attacker = vm("ssc-attacker", ipv4=("192.168.64.12",))
    with pytest.raises(gi.InventoryError, match=message):
        gi.lab_hosts(listing(node, attacker), "small")


def test_network_is_the_slash_24_around_the_node() -> None:
    assert gi.lab_network(gi.lab_hosts(FULL, "full")) == NET


def test_vm_outside_the_network_is_refused_unless_overridden() -> None:
    hosts = gi.lab_hosts(
        listing(vm("ssc-node"), vm("ssc-attacker", ipv4=("192.168.65.12",))), "small"
    )
    with pytest.raises(gi.InventoryError, match="not inside 192.168.64.0/24"):
        gi.lab_network(hosts)
    assert gi.lab_network(hosts, "192.168.64.0/23") == IPv4Network("192.168.64.0/23")


def test_public_network_override_is_refused() -> None:
    with pytest.raises(gi.InventoryError, match="not private"):
        gi.lab_network(gi.lab_hosts(FULL, "full"), "8.8.0.0/16")


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


def test_inventory_vars_and_groups(tmp_path: Path) -> None:
    hosts = gi.lab_hosts(FULL, "full")
    inventory = gi.build_inventory(hosts, "full", NET, CONTROLLER, "ssc-admin", tmp_path)
    variables = inventory["all"]["vars"]
    assert variables["ansible_user"] == "ssc-admin"
    key = Path(variables["ansible_ssh_private_key_file"])
    assert key.is_absolute()
    assert key == tmp_path / ".lab" / "keys" / "ssc_admin_ed25519"
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
    hosts = gi.lab_hosts(SMALL, "small")
    inventory = gi.build_inventory(hosts, "small", NET, CONTROLLER, "ssc-admin", tmp_path)
    groups = {g: list(c["hosts"]) for g, c in inventory["all"]["children"].items()}
    assert groups == {"node": ["ssc-node"], "monitor": ["ssc-node"], "attacker": ["ssc-attacker"]}
    assert inventory["all"]["vars"]["lab_profile"] == "small"


@pytest.mark.parametrize(
    ("controller", "message"),
    [("10.0.0.1", "not inside"), ("192.168.64.10", "is a lab VM address")],
)
def test_bad_controller_ip_is_refused(tmp_path: Path, controller: str, message: str) -> None:
    hosts = gi.lab_hosts(FULL, "full")
    with pytest.raises(gi.InventoryError, match=message):
        gi.build_inventory(hosts, "full", NET, IPv4Address(controller), "ssc-admin", tmp_path)


def test_ssh_config_blocks(tmp_path: Path) -> None:
    text = gi.render_ssh_config(gi.lab_hosts(FULL, "full"), "ssc-admin", tmp_path)
    assert "Host ssc-node\n  HostName 192.168.64.10\n  User ssc-admin\n" in text
    assert f'IdentityFile "{tmp_path / ".lab" / "keys" / "ssc_admin_ed25519"}"' in text
    assert text.count("IdentitiesOnly yes") == 3
    assert "StrictHostKeyChecking no" not in text


def run_cli(tmp_path: Path, fixture: str = "multipass_list_full.json") -> int:
    return gi.main(
        [
            "--multipass-json",
            str(FIXTURES / fixture),
            "--controller-ip",
            "192.168.64.1",
            "--root",
            str(tmp_path),
        ]
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
    assert not (tmp_path / "inventory" / "lab.yml").exists()


def test_example_inventory_has_the_same_vars_as_generated(tmp_path: Path) -> None:
    hosts = gi.lab_hosts(FULL, "full")
    generated = gi.build_inventory(hosts, "full", NET, CONTROLLER, "ssc-admin", tmp_path)
    example = yaml.safe_load((ROOT / "inventory" / "lab.yml.example").read_text())
    assert set(example["all"]["vars"]) == set(generated["all"]["vars"])
    assert set(example["all"]["children"]) == set(generated["all"]["children"])
