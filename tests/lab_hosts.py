"""testinfra host lists for tests that need the lab VMs (marked `lab`).

testinfra expands `ansible://<group>` while pytest collects tests, even for
`make test`, which then deselects them. Without inventory/lab.yml (CI, or
before `make lab-up`) that expansion fails, so the module is skipped instead.

testinfra does not understand Ansible patterns such as `node:monitor`; an
unknown pattern matches no host, and the tests would be skipped and look like
a pass. So this takes plain group names and fails when one has no hosts.
"""

from pathlib import Path

import pytest
import yaml

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "lab.yml"


def address(name: str) -> str:
    """`ansible_host` of one inventory host, such as "ssc-attacker"."""
    for group in yaml.safe_load(INVENTORY.read_text())["all"]["children"].values():
        found = ((group or {}).get("hosts") or {}).get(name)
        if found:
            return found["ansible_host"]
    raise RuntimeError(f"host {name!r} is not in {INVENTORY}")


def unban_attacker(host) -> None:
    """Lift any fail2ban ban on ssc-attacker on this host.

    The attacker is bannable on purpose (scenario S1), so every test that makes
    a refused login from it adds to fail2ban's failure count, and a ban would
    break the next test that connects from it. Before the fail2ban role has
    run there is nothing to lift.
    """
    with host.sudo():
        if host.run("systemctl is-active --quiet fail2ban").rc == 0:
            host.check_output(f"fail2ban-client unban {address('ssc-attacker')}")


def hosts(*groups: str) -> list[str]:
    """`testinfra_hosts` for inventory groups such as "all", "node", "monitor"."""
    if not INVENTORY.exists():
        pytest.skip("needs the lab VMs: run `make lab-up` first", allow_module_level=True)
    children = yaml.safe_load(INVENTORY.read_text())["all"]["children"]
    for group in groups:
        if group != "all" and not (children.get(group) or {}).get("hosts"):
            raise RuntimeError(f"inventory group {group!r} has no hosts in {INVENTORY}")
    return [f"ansible://{group}" for group in groups]
