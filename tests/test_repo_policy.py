"""Repo policy checks for CLAUDE.md rules 6 (no secrets in git), 7 (pinned
versions) and 9 (ask before destructive actions). These need no VMs."""

import configparser
import json
import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
EXACT_VERSION = re.compile(r"^\d+(\.\d+)+$")

# Row names in docs/VERSIONS.md that differ from the package name.
VERSIONS_ROW_NAME = {"shellcheck-py": "shellcheck (shellcheck-py)"}


def python_pins() -> dict[str, str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    specs = list(data["project"]["dependencies"])
    for group in data["dependency-groups"].values():
        specs.extend(group)
    pins = {}
    for spec in specs:
        name, sep, version = spec.partition("==")
        assert sep and EXACT_VERSION.match(version), f"not pinned exactly: {spec}"
        pins[name] = version
    return pins


def collection_pins() -> dict[str, str]:
    data = yaml.safe_load((ROOT / "requirements.yml").read_text())
    pins = {}
    for item in data["collections"]:
        version = str(item.get("version", ""))
        assert EXACT_VERSION.match(version), f"not pinned exactly: {item}"
        pins[item["name"]] = version
    return pins


def versions_table() -> dict[str, str]:
    rows = {}
    for line in (ROOT / "docs" / "VERSIONS.md").read_text().splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4:
            rows[cells[0]] = cells[1]
    return rows


def test_python_dependencies_pinned_exactly() -> None:
    assert python_pins()


def test_collections_pinned_exactly() -> None:
    assert collection_pins()


def test_every_pin_recorded_in_versions_md() -> None:
    table = versions_table()
    for name, version in {**python_pins(), **collection_pins()}.items():
        row = VERSIONS_ROW_NAME.get(name, name)
        assert row in table, f"docs/VERSIONS.md has no row for {row}"
        recorded = table[row]
        assert recorded.startswith(version), f"{row}: recorded {recorded!r}, pinned {version}"


def test_ansible_cfg_uses_generated_inventory_file() -> None:
    cfg = configparser.ConfigParser()
    cfg.read(ROOT / "ansible.cfg")
    assert cfg["defaults"]["inventory"] == "inventory/lab.yml"
    assert cfg["defaults"]["collections_path"] == ".ansible/collections"


def test_secret_and_generated_paths_are_gitignored() -> None:
    ignored = set((ROOT / ".gitignore").read_text().split())
    for path in (".lab/", "inventory/lab.yml", ".venv/", ".ansible/"):
        assert path in ignored, f"{path} missing from .gitignore"


def test_claude_permissions_guard_destructive_actions() -> None:
    perms = json.loads((ROOT / ".claude" / "settings.json").read_text())["permissions"]
    for rule in (
        "Bash(git push --force:*)",
        "Bash(git push -f:*)",
        "Bash(git push --force-with-lease:*)",
        "Read(./.lab/keys/**)",
    ):
        assert rule in perms["deny"], f"{rule} must be denied"
    for rule in (
        "Bash(make lab-down:*)",
        "Bash(multipass delete:*)",
        "Bash(multipass purge:*)",
        "Bash(multipass restore:*)",
    ):
        assert rule in perms["ask"], f"{rule} must ask first"
