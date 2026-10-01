"""testinfra host lists for tests that need the lab VMs (marked `lab`).

testinfra expands `ansible://<pattern>` while pytest collects tests, even for
`make test`, which then deselects them. Without inventory/lab.yml (CI, or
before `make lab-up`) that expansion fails, so the module is skipped instead.
"""

from pathlib import Path

import pytest

INVENTORY = Path(__file__).resolve().parent.parent / "inventory" / "lab.yml"


def hosts(pattern: str) -> list[str]:
    """`testinfra_hosts` for an inventory pattern such as "all" or "node"."""
    if not INVENTORY.exists():
        pytest.skip("needs the lab VMs: run `make lab-up` first", allow_module_level=True)
    return [f"ansible://{pattern}"]
