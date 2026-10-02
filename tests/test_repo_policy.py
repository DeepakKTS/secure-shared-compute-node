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
    # Claude Code writes the owner's own permission rules here.
    ".claude/settings.local.json",
)


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=False)


@pytest.mark.parametrize("path", SECRET_PATHS)
def test_secret_and_generated_paths_are_gitignored(path: str) -> None:
    # The rule must come from the repo's .gitignore. A global ignore file or
    # .git/info/exclude covers only this machine, not a fresh clone.
    result = git("check-ignore", "-v", "--no-index", path)
    assert result.returncode == 0, f"{path} not ignored"
    source = result.stdout.split(":", 1)[0]
    assert source == ".gitignore", f"{path} ignored only by {source}, not the repo's .gitignore"


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
        # The lab keys live outside the repo (scripts/lab.sh KEY_DIR).
        "Read(~/.config/ssc-lab/keys/**)",
    ):
        assert rule in perms["deny"], f"{rule} must be denied"
    assert "Bash(ssh:*)" not in perms["allow"], "ssh to any host breaks rule 1 (lab only)"
    # python3 -c could drive a pty past the lab-down prompt, or run ssh and
    # multipass directly, skipping the ask list. The user removed it. Since
    # 2026-10-01 the owner allows `Bash(.venv/bin/*)` and `Bash(uv:*)`, which
    # let `.venv/bin/python -c` and `uv run` do the same. The guard hook still
    # blocks deletes written as code; this check covers only the system python3.
    assert "Bash(python3:*)" not in perms["allow"], "python3 must not be auto-allowed"
    for rule in (
        "Bash(make lab-down:*)",
        "Bash(multipass delete:*)",
        "Bash(multipass purge:*)",
        "Bash(multipass restore:*)",
        "Bash(git reset:*)",
        "Bash(git rebase:*)",
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
        # The allow list has `git branch:*` and `gh run:*`; ask wins over
        # allow, so these still prompt.
        "Bash(git branch -D:*)",
        "Bash(gh run delete:*)",
    ):
        assert rule in perms["ask"], f"{rule} must ask first"


def test_claude_gh_api_allow_rule_is_read_only() -> None:
    # One exact command, the ruleset check in CLAUDE.md section 8, item 9. No
    # wildcard, so `-X DELETE` or another endpoint does not match it.
    perms = json.loads((ROOT / ".claude" / "settings.json").read_text())["permissions"]
    gh_api = [rule for rule in perms["allow"] if rule.startswith("Bash(gh api")]
    assert gh_api == ["Bash(gh api repos/DeepakKTS/secure-shared-compute-node/rules/branches/main)"]


def rule_matches(rule: str, command: str) -> bool:
    """Whether a Claude Code Bash rule matches a command: `*` is any text and a
    trailing `:*` means a trailing ` *` (code.claude.com/docs/en/permissions)."""
    if rule == "Bash":
        return True
    match = re.fullmatch(r"Bash\((.*)\)", rule, re.DOTALL)
    if not match:
        return False
    pattern = match.group(1)
    if pattern.endswith(":*"):
        pattern = pattern[:-2] + " *"
    regex = ".*".join(re.escape(part) for part in pattern.split("*"))
    return re.fullmatch(regex, command, re.DOTALL) is not None


# Commands an allow rule in settings.local.json must not match. Nothing here
# is run. The addresses are documentation ranges (RFC 5737), never the lab.
UNRESTRICTED_PROBES = {
    "ssh": ["ssh 203.0.113.5 true", "/usr/bin/ssh -o BatchMode=yes 203.0.113.5 true"],
    "curl": ["curl https://example.com/x", "/usr/bin/curl -s https://example.com/x"],
    "wget": ["wget https://example.com/x", "/usr/bin/wget -q https://example.com/x"],
    "python": [
        "python3 -c 'print(1)'",
        "python -c 'print(1)'",
        "/usr/bin/python3 -c 'print(1)'",
        ".venv/bin/python -c 'print(1)'",
        "python3 /tmp/any.py",
    ],
    "gh api": [
        "gh api repos/DeepakKTS/secure-shared-compute-node -X DELETE",
        "gh api graphql -f query=x",
    ],
    # A browser fetches any URL it is given, as curl does. `open` and
    # `xdg-open` hand a URL to the default browser.
    "browser": [
        "open https://example.com/x",
        "/usr/bin/open -a Safari https://example.com/x",
        "xdg-open https://example.com/x",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome https://example.com/x",
        '"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" https://example.com/x',
        "/Applications/Google\\ Chrome.app/Contents/MacOS/Google\\ Chrome https://example.com/x",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --headless=new"
        " --screenshot=x.png https://example.com/x",
        "/Applications/Chromium.app/Contents/MacOS/Chromium https://example.com/x",
        "/Applications/Firefox.app/Contents/MacOS/firefox https://example.com/x",
        "/Applications/Safari.app/Contents/MacOS/Safari https://example.com/x",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge https://example.com/x",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser https://example.com/x",
        "google-chrome https://example.com/x",
        "chromium --headless https://example.com/x",
        "firefox https://example.com/x",
    ],
}


def unrestricted_rules(allow: list[str]) -> list[tuple[str, str]]:
    return [
        (tool, rule)
        for rule in allow
        for tool, probes in UNRESTRICTED_PROBES.items()
        if any(rule_matches(rule, probe) for probe in probes)
    ]


@pytest.mark.parametrize(
    "rule",
    [
        "Bash",
        "Bash(*)",
        "Bash(ssh:*)",
        "Bash(ssh *)",
        "Bash(curl:*)",
        "Bash(wget *)",
        "Bash(python3:*)",
        "Bash(python -c:*)",
        "Bash(/usr/bin/*)",
        "Bash(.venv/bin/*)",
        "Bash(gh:*)",
        "Bash(gh api:*)",
        "Bash(gh api *)",
        "Bash(/Applications/Google Chrome.app/Contents/MacOS/Google Chrome *)",
        'Bash("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome":*)',
        "Bash(/Applications/*)",
        "Bash(open:*)",
        "Bash(open *)",
        "Bash(/usr/bin/open:*)",
        "Bash(xdg-open:*)",
        "Bash(firefox *)",
        "Bash(chromium:*)",
    ],
)
def test_unrestricted_rule_is_found(rule: str) -> None:
    assert unrestricted_rules([rule]), f"{rule} should count as unrestricted"


@pytest.mark.parametrize(
    "rule",
    [
        "Bash(ssh -F .lab/ssh_config ssc-node:*)",
        "Bash(.venv/bin/python -B scripts/demo.py --html)",
        "Bash(gh api repos/DeepakKTS/secure-shared-compute-node/rules/branches/main)",
        "Bash(gh run:*)",
        "Bash(git branch *)",
        "Read(//private/tmp/**)",
        # One fixed local page, as in the shared settings.
        "Bash(open .lab/demo/index.html)",
        'Bash("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new'
        " --screenshot=x.png file:///Users/x/repo/.lab/demo/index.html)",
    ],
)
def test_restricted_rule_is_not_flagged(rule: str) -> None:
    assert unrestricted_rules([rule]) == []


def test_claude_local_settings_allow_nothing_unrestricted() -> None:
    # The owner's own .claude/settings.local.json (gitignored, absent in CI)
    # must not undo rule 1 or the python3 decision with a broad allow rule,
    # or let a browser fetch any URL.
    local = ROOT / ".claude" / "settings.local.json"
    if not local.exists():
        return
    allow = json.loads(local.read_text()).get("permissions", {}).get("allow", [])
    found = unrestricted_rules(allow)
    assert found == [], f"settings.local.json allows too much: {found}"


def test_claude_ssh_allow_rules_name_only_lab_hosts() -> None:
    # Rule 1 (lab only): an auto-allowed ssh must go through the generated
    # .lab/ssh_config to one of the three lab VMs, never a bare host.
    perms = json.loads((ROOT / ".claude" / "settings.json").read_text())["permissions"]
    vms = ("ssc-node", "ssc-monitor", "ssc-attacker")
    lab = {f"Bash(ssh -F .lab/ssh_config {vm}:*)" for vm in vms}
    ssh_rules = {rule for rule in perms["allow"] if rule.startswith("Bash(ssh")}
    assert ssh_rules <= lab, f"ssh allow rules outside the lab: {sorted(ssh_rules - lab)}"


def test_claude_permission_rules_use_supported_wildcards() -> None:
    # Claude Code reads `:*` only at the end of a rule; elsewhere the colon is
    # a literal character and the rule matches nothing it was meant to
    # (code.claude.com/docs/en/permissions, "Wildcard patterns").
    perms = json.loads((ROOT / ".claude" / "settings.json").read_text())["permissions"]
    for kind in ("allow", "ask", "deny"):
        for rule in perms[kind]:
            assert ":*" not in rule[:-2], f"{kind} rule {rule!r} has :* before its end"
