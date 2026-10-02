"""Unit tests for roles/auditd, with no VM. Most render
templates/ssc.rules.j2 for each architecture the role supports, so the x86_64
rules (both arch=b64 and arch=b32), which the arm64 lab cannot run, are
checked too. Ansible renders templates with Jinja2 and trim_blocks; this does
the same. The rest read the role's tasks.
"""

import re
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "roles" / "auditd"
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
NODE_VARS = yaml.safe_load((ROOT / "inventory" / "group_vars" / "node.yml").read_text())
ARCHES = {"aarch64": ["b64"], "x86_64": ["b64", "b32"]}


def render_text(arch: str) -> str:
    env = jinja2.Environment(
        trim_blocks=True, keep_trailing_newline=True, undefined=jinja2.StrictUndefined
    )
    template = env.from_string((ROLE / "templates" / "ssc.rules.j2").read_text())
    return template.render(
        **DEFAULTS,
        users_research=NODE_VARS["users_research"],
        ansible_facts={"architecture": arch},
    )


def rules(arch: str) -> list[str]:
    return [line for line in render_text(arch).splitlines() if re.match(r"-[aw] ", line)]


def test_defaults_cover_the_same_architectures() -> None:
    assert DEFAULTS["auditd_syscall_arches"] == ARCHES
    assert set(DEFAULTS["auditd_chmod_syscalls"]) == set(ARCHES)


@pytest.mark.parametrize(("arch", "abis"), sorted(ARCHES.items()))
def test_every_syscall_rule_is_written_for_each_abi(arch: str, abis: list[str]) -> None:
    syscall_rules = [rule for rule in rules(arch) if rule.startswith("-a ")]
    per_abi = {
        abi: [rule.replace(f"arch={abi} ", "arch=ABI ") for rule in syscall_rules
              if f"-F arch={abi} " in rule]
        for abi in abis
    }  # fmt: skip
    assert sum(len(found) for found in per_abi.values()) == len(syscall_rules)
    assert per_abi[abis[0]], f"no syscall rules for {arch}"
    for abi in abis[1:]:
        assert per_abi[abi] == per_abi[abis[0]], abi


def test_x86_64_has_chmod_and_aarch64_does_not() -> None:
    # aarch64 has no plain chmod syscall; auditctl would refuse the name.
    assert any(re.search(r"-S chmod,fchmod ", rule) for rule in rules("x86_64"))
    assert not any(re.search(r"[ ,]chmod[ ,]", rule) for rule in rules("aarch64"))


@pytest.mark.parametrize("arch", sorted(ARCHES))
def test_exec_rules_cover_each_temp_path_without_a_success_filter(arch: str) -> None:
    exec_rules = [rule for rule in rules(arch) if rule.endswith("-k ssc_exec_tmp")]
    assert not [rule for rule in exec_rules if "success" in rule]
    for abi in ARCHES[arch]:
        for path in DEFAULTS["auditd_exec_paths"]:
            assert (
                f"-a always,exit -F arch={abi} -S execve,execveat -F dir={path} -k ssc_exec_tmp"
                in exec_rules
            ), (abi, path)


@pytest.mark.parametrize("arch", sorted(ARCHES))
def test_setid_rules_test_the_mode_argument(arch: str) -> None:
    setid = [rule for rule in rules(arch) if rule.endswith("-k ssc_suid")]
    groups = DEFAULTS["auditd_chmod_syscalls"][arch]
    assert len(setid) == len(groups) * len(ARCHES[arch])
    for rule in setid:
        assert re.search(r" -F a[12]&06000 -k ssc_suid$", rule), rule


@pytest.mark.parametrize("arch", sorted(ARCHES))
def test_every_rule_has_an_ssc_key(arch: str) -> None:
    for rule in rules(arch):
        assert re.search(r" -k ssc_\w+$", rule), rule


def test_each_research_user_gets_their_own_watches() -> None:
    found = rules("aarch64")
    for user in NODE_VARS["users_research"]:
        for name in DEFAULTS["auditd_user_dirs"] + DEFAULTS["auditd_user_rc_files"]:
            assert f"-w /home/{user['name']}/{name} -p wa -k ssc_user_persist" in found


def test_control_lines_keep_audit_mutable_and_failure_mode_1() -> None:
    controls = [line for line in render_text("aarch64").splitlines() if re.match(r"-[bfe] ", line)]
    assert controls == [f"-b {DEFAULTS['auditd_backlog_limit']}", "-f 1", "-e 1"]


def tasks() -> list[dict]:
    return yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())


def module(task: dict) -> str:
    return next(key for key in task if key.startswith("ansible."))


def test_role_installs_auditd_before_anything_else_touches_the_host() -> None:
    # A fresh node has no auditd. The lab node got it by hand before the role
    # ran (docs/PROGRESS.md, P2.8), so a lab run alone does not prove the role
    # installs it. This does: the role's first task that acts on the host is
    # an unconditional apt install of auditd.
    acting = [task for task in tasks() if module(task) != "ansible.builtin.assert"]
    first = acting[0]
    assert module(first) == "ansible.builtin.apt", first
    assert first["ansible.builtin.apt"]["name"] == "auditd"
    assert first["ansible.builtin.apt"]["state"] == "present"
    assert "when" not in first and "never" not in first.get("tags", [])


def test_rules_file_sorts_after_the_vendor_rules() -> None:
    # augenrules reads rules.d in `ls -v` order and keeps the last -b, -f and
    # -e, so the role's file must come after the vendor's audit.rules.
    dest = next(
        task["ansible.builtin.template"]["dest"]
        for task in tasks()
        if task.get("ansible.builtin.template", {}).get("src") == "ssc.rules.j2"
    )
    assert Path(dest).parent == Path("/etc/audit/rules.d")
    assert Path(dest).name > "audit.rules"
