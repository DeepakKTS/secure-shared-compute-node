"""Unit tests for tests/lab_hosts.py. No VMs: a temp inventory stands in."""

from pathlib import Path

import lab_hosts
import pytest
import yaml


def inventory(tmp_path: Path, children: dict) -> Path:
    path = tmp_path / "lab.yml"
    path.write_text(yaml.safe_dump({"all": {"children": children}}))
    return path


def test_known_groups_become_ansible_urls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    children = {"node": {"hosts": {"ssc-node": {}}}, "monitor": {"hosts": {"ssc-monitor": {}}}}
    monkeypatch.setattr(lab_hosts, "INVENTORY", inventory(tmp_path, children))
    assert lab_hosts.hosts("node", "monitor") == ["ansible://node", "ansible://monitor"]
    assert lab_hosts.hosts("all") == ["ansible://all"]


@pytest.mark.parametrize("group", ["node:monitor", "nosuch", "empty"])
def test_unknown_or_empty_group_fails_instead_of_skipping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, group: str
) -> None:
    children = {"node": {"hosts": {"ssc-node": {}}}, "empty": {"hosts": {}}}
    monkeypatch.setattr(lab_hosts, "INVENTORY", inventory(tmp_path, children))
    with pytest.raises(RuntimeError, match="has no hosts"):
        lab_hosts.hosts(group)


def test_missing_inventory_skips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lab_hosts, "INVENTORY", tmp_path / "absent.yml")
    with pytest.raises(pytest.skip.Exception):
        lab_hosts.hosts("node")
