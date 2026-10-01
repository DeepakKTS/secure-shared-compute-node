"""Repo policy checks for CLAUDE.md rules 6 (no secrets in git), 7 (pinned
versions) and 9 (ask before destructive actions). These need no VMs."""

import configparser
import json
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
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


def test_python_and_uv_pinned_exactly_and_recorded() -> None:
    python = (ROOT / ".python-version").read_text().strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", python), f".python-version not exact: {python!r}"
    uv = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["uv"]
    assert uv["python-preference"] == "only-managed"
    required = uv["required-version"]
    assert required.startswith("==") and EXACT_VERSION.match(required[2:]), required
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    setup_uv = [s for s in ci["jobs"]["lint-and-test"]["steps"] if "setup-uv" in s.get("uses", "")]
    assert setup_uv[0]["with"]["version"] == required[2:], "CI and pyproject.toml pin different uv"
    table = versions_table()
    assert table["Python (controller)"].startswith(python)
    assert table["uv"].startswith(required[2:])


def test_lynis_pin_matches_versions_md() -> None:
    play = yaml.safe_load((ROOT / "playbooks" / "audit.yml").read_text())[0]
    version = play["vars"]["audit_lynis_version"]
    assert EXACT_VERSION.match(version), f"Lynis not pinned exactly: {version}"
    assert re.fullmatch(r"[0-9a-f]{64}", play["vars"]["audit_lynis_sha256"])
    recorded = versions_table()["Lynis"]
    assert re.match(rf"{re.escape(version)}\b(?!\.)", recorded), (
        f"VERSIONS.md has {recorded!r}, audit.yml pins {version}"
    )
    assert play["vars"]["audit_lynis_sha256"] in recorded


def test_ansible_cfg_uses_generated_inventory_file() -> None:
    cfg = configparser.ConfigParser()
    cfg.read(ROOT / "ansible.cfg")
    assert cfg["defaults"]["inventory"] == "inventory/lab.yml"
    assert cfg["defaults"]["collections_path"] == ".ansible/collections"


# Real paths that hold keys, lab IPs or passwords. Ask git, not the file text.
SECRET_PATHS = (
    ".lab/keys/ssc_admin_ed25519",
    ".lab/keys/ssc_admin_ed25519.pub",
    ".lab/cloud-init.yaml",
    ".lab/ssh_config",
    ".lab/known_hosts",
    ".lab/vault_pass",
    ".lab/audit/bash.log",
    ".vault_pass",
    "inventory/lab.yml",
    "inventory/.lab.yml.tmp",
    ".venv/bin/python",
    ".ansible/collections/x",
)


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)


@pytest.mark.parametrize("path", SECRET_PATHS)
def test_secret_and_generated_paths_are_gitignored(path: str) -> None:
    assert git("check-ignore", "-q", "--no-index", path).returncode == 0, f"{path} not ignored"


def test_example_inventory_is_not_ignored() -> None:
    assert git("check-ignore", "-q", "--no-index", "inventory/lab.yml.example").returncode == 1


def test_no_lab_file_is_tracked() -> None:
    tracked = git("ls-files", "--", ".lab", "inventory/lab.yml", "inventory/.lab.yml.tmp")
    assert tracked.returncode == 0
    assert tracked.stdout == "", f"tracked lab files: {tracked.stdout}"


def test_claude_permissions_guard_destructive_actions() -> None:
    perms = json.loads((ROOT / ".claude" / "settings.json").read_text())["permissions"]
    for rule in (
        "Bash(git push --force:*)",
        "Bash(git push -f:*)",
        "Bash(git push --force-with-lease:*)",
        "Read(./.lab/keys/**)",
    ):
        assert rule in perms["deny"], f"{rule} must be denied"
    assert "Bash(ssh:*)" not in perms["allow"], "ssh to any host breaks rule 1 (lab only)"
    # python3 -c could drive a pty past the lab-down prompt, or run ssh and
    # multipass directly, skipping the ask list. The user removed it.
    assert "Bash(python3:*)" not in perms["allow"], "python3 must not be auto-allowed"
    for rule in (
        "Bash(make lab-down:*)",
        "Bash(multipass delete:*)",
        "Bash(multipass purge:*)",
        "Bash(multipass restore:*)",
        # Recursive deletes on the host ask first (docs/AUTONOMY.md). Rules
        # match the command text as written: `rm -R:*` means `rm -R *`, so
        # it misses `rm -Rf x`, and `bash -c 'rm -r x'` escapes all of them.
        # The AUTONOMY rule still applies to those.
        "Bash(rm -rf:*)",
        "Bash(rm -r:*)",
        "Bash(rm -fr:*)",
        "Bash(rm -R:*)",
        "Bash(/bin/rm:*)",
        # `*` works anywhere in a rule; no space before the last `*`, so
        # `-delete` at the end matches too.
        "Bash(find * -delete*)",
    ):
        assert rule in perms["ask"], f"{rule} must ask first"


def test_claude_permission_rules_use_supported_wildcards() -> None:
    # Claude Code reads `:*` only at the end of a rule; elsewhere the colon is
    # a literal character and the rule matches nothing it was meant to
    # (code.claude.com/docs/en/permissions, "Wildcard patterns").
    perms = json.loads((ROOT / ".claude" / "settings.json").read_text())["permissions"]
    for kind in ("allow", "ask", "deny"):
        for rule in perms[kind]:
            assert ":*" not in rule[:-2], f"{kind} rule {rule!r} has :* before its end"
