"""Make scripts/ importable in tests (for example `import gen_inventory`), and
shared fixtures for the lab tests."""

import sys
from pathlib import Path

import lab_hosts
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


@pytest.fixture
def attacker_unbanned(host):
    """For lab tests that connect from ssc-attacker: no fail2ban ban on this
    host before the test, and none left behind after it."""
    lab_hosts.unban_attacker(host)
    yield
    lab_hosts.unban_attacker(host)
