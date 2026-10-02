"""State tests for roles/auditd on the node (F-27). They need the lab: run
`make verify`, or `pytest -m lab tests/test_auditd.py` with .venv/bin on PATH.
Expected values come from the role defaults and the inventory.

The record tests do what S2 and S5 will do (an exec from a temp path, a write
to a persistence path, a setuid bit) and find the record by its key. They
make and remove small files, so they are marked changes_state.
"""

import re
import secrets
import time
from pathlib import Path

import lab_hosts
import pytest
import yaml

pytestmark = pytest.mark.lab
testinfra_hosts = lab_hosts.hosts("node")

ROOT = Path(__file__).resolve().parent.parent
DEFAULTS = yaml.safe_load((ROOT / "roles" / "auditd" / "defaults" / "main.yml").read_text())
RULES_FILE = "/etc/audit/rules.d/ssc.rules"
KEY = re.compile(r"(?:-k |key=)(ssc_\w+)")
FCHMODAT2 = (
    'python3 -c "import ctypes;'
    " assert ctypes.CDLL(None).syscall(452, -100, b'{f}', 0o4755, 0) == 0\""
)


def research_users(host) -> list[str]:
    return [user["name"] for user in host.ansible.get_variables()["users_research"]]


def loaded(host) -> list[str]:
    """Rules the kernel holds now, as `auditctl -l` prints them."""
    with host.sudo():
        return host.check_output("auditctl -l").splitlines()


def loaded_with_key(host, key: str) -> list[str]:
    return [rule for rule in loaded(host) if (m := KEY.search(rule)) and m.group(1) == key]


def arches(host) -> list[str]:
    return DEFAULTS["auditd_syscall_arches"][host.system_info.arch]


def now(host) -> float:
    return float(host.check_output("date +%s.%N"))


def events(host, key: str, since: float, success: str | None = None) -> list[str]:
    """Raw events for `key` from `since` (epoch seconds) on, newest last.
    auditd writes asynchronously, so wait a little for them. ausearch reads
    stdin when it is not a terminal, as here, so --input-logs points it at
    the log (without it, it finds nothing)."""
    flag = f"--success {success}" if success else ""
    found: list[str] = []
    for _ in range(10):
        with host.sudo():
            out = host.run(f"ausearch --input-logs -k {key} {flag} -ts recent").stdout
        found = [
            event
            for event in out.split("----")
            if (stamp := re.search(r"msg=audit\((\d+\.\d+):", event))
            and float(stamp.group(1)) >= since - 1
        ]
        if found:
            return found
        time.sleep(1)
    return found


def uid(host, user: str) -> str:
    return host.check_output(f"id -u {user}")


# ---- configuration -------------------------------------------------------


def test_auditd_runs_at_boot(host) -> None:
    assert host.package("auditd").is_installed
    assert host.service("auditd").is_enabled
    assert host.run("systemctl is-active auditd").stdout.strip() == "active"


def test_audit_is_enabled_not_immutable_and_logs_failures(host) -> None:
    with host.sudo():
        status = dict(line.split(" ", 1) for line in host.check_output("auditctl -s").splitlines())
    # enabled 2 would be immutable: no rule change until a reboot.
    assert status["enabled"] == "1", status
    # failure 1 logs a lost record and goes on; 2 would panic the kernel.
    assert status["failure"] == "1", status
    assert int(status["backlog_limit"]) == DEFAULTS["auditd_backlog_limit"]


def test_no_rule_file_makes_the_rules_immutable(host) -> None:
    with host.sudo():
        lines = host.check_output("cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules")
    assert not re.search(r"^\s*-e\s+2", lines, re.M)


def test_every_rule_in_the_file_is_loaded(host) -> None:
    # The unit loads rules with `ExecStartPost=-augenrules --load`, and the
    # leading `-` hides a failed load. So compare the kernel with the file.
    with host.sudo():
        text = host.check_output(f"cat {RULES_FILE}")
    in_file = [line for line in text.splitlines() if re.match(r"-[aw] ", line)]
    assert in_file
    assert len([rule for rule in loaded(host) if KEY.search(rule)]) == len(in_file)


def test_exec_from_each_temp_path_has_a_rule_without_success_filter(host) -> None:
    rules = loaded_with_key(host, "ssc_exec_tmp")
    assert not [rule for rule in rules if "success" in rule], rules
    for arch in arches(host):
        for path in DEFAULTS["auditd_exec_paths"]:
            assert any(
                f"arch={arch}" in rule
                and re.search(r"-S execve,execveat\b", rule)
                and f"dir={path} " in f"{rule} "
                for rule in rules
            ), (arch, path, rules)


def test_setid_chmod_has_rules_for_every_mode_argument(host) -> None:
    rules = loaded_with_key(host, "ssc_suid")
    calls = DEFAULTS["auditd_chmod_syscalls"][host.system_info.arch]
    assert len(rules) == len(calls) * len(arches(host)), rules
    for rule in rules:
        # auditctl 3.1.2 prints the 06000 mask in hex, as `a1&0xC00`.
        assert re.search(r"-F a[12]&0xC00 ", rule), rule


@pytest.mark.parametrize(
    ("var", "key"),
    [
        ("auditd_cron_paths", "ssc_cron"),
        ("auditd_systemd_paths", "ssc_systemd"),
        ("auditd_sudoers_paths", "ssc_sudoers"),
    ],
)
def test_persistence_paths_are_watched(host, var: str, key: str) -> None:
    rules = loaded_with_key(host, key)
    for path in DEFAULTS[var]:
        assert any(f" {path} " in rule or f"={path} " in rule for rule in rules), (path, rules)


def test_each_research_users_paths_are_watched(host) -> None:
    rules = loaded_with_key(host, "ssc_user_persist")
    for user in research_users(host):
        for name in DEFAULTS["auditd_user_dirs"] + DEFAULTS["auditd_user_rc_files"]:
            path = f"/home/{user}/{name}"
            assert any(f" {path} " in rule or f"={path} " in rule for rule in rules), path


def test_watched_user_directories_exist_and_are_private(host) -> None:
    # A watch on a missing directory is not recursive, so the role makes them.
    for user in research_users(host):
        for name in DEFAULTS["auditd_user_dirs"]:
            with host.sudo():
                d = host.file(f"/home/{user}/{name}")
                assert d.is_directory, d.path
                assert (d.user, d.group, d.mode) == (user, user, 0o700), d.path


@pytest.mark.parametrize(
    ("key", "var"),
    [
        ("max_log_file", "auditd_max_log_file"),
        ("num_logs", "auditd_num_logs"),
        ("space_left", "auditd_space_left"),
        ("space_left_action", "auditd_space_left_action"),
        ("admin_space_left", "auditd_admin_space_left"),
        ("admin_space_left_action", "auditd_admin_space_left_action"),
        ("disk_full_action", "auditd_disk_full_action"),
        ("disk_error_action", "auditd_disk_error_action"),
    ],
)
def test_auditd_conf_has_the_chosen_value(host, key: str, var: str) -> None:
    with host.sudo():
        text = host.check_output("cat /etc/audit/auditd.conf")
    conf = dict(re.findall(r"^(\w+) = (.*)$", text, re.M))
    assert conf[key].lower() == str(DEFAULTS[var]).lower()


def test_no_disk_action_stops_the_machine(host) -> None:
    # single or halt would let any user who fills the disk take the shared
    # node down for everyone (role README).
    with host.sudo():
        text = host.check_output("cat /etc/audit/auditd.conf")
    actions = re.findall(r"^\w*_action = (\w+)", text, re.M)
    assert actions and not {a.lower() for a in actions} & {"single", "halt"}, actions


# ---- records -------------------------------------------------------------


@pytest.mark.changes_state
@pytest.mark.parametrize("path", ["/tmp", "/dev/shm"])
def test_refused_exec_from_a_noexec_path_is_recorded(host, path: str) -> None:
    # What S2 will look for: the dropper's exec fails with EACCES on the
    # noexec mount, and that failed attempt is in the audit log.
    binary = f"{path}/ssc-exec-{secrets.token_hex(4)}"
    since = now(host)
    with host.sudo("alice"):
        host.check_output(f"cp /bin/true {binary} && chmod 0755 {binary}")
        result = host.run(binary)
        host.run(f"rm -f {binary}")
    assert result.rc == 126, result
    found = [e for e in events(host, "ssc_exec_tmp", since, success="no") if binary in e]
    assert found, f"no failed exec record for {binary}"
    assert "success=no" in found[-1] and "exit=-13" in found[-1], found[-1]
    assert f" uid={uid(host, 'alice')} " in found[-1], found[-1]


@pytest.mark.changes_state
def test_exec_from_var_tmp_is_recorded(host) -> None:
    # /var/tmp is not noexec (role tmp_hardening README), so the run works,
    # and the record says so.
    binary = f"/var/tmp/ssc-exec-{secrets.token_hex(4)}"
    since = now(host)
    with host.sudo("alice"):
        host.check_output(f"cp /bin/true {binary} && chmod 0755 {binary}")
        result = host.run(binary)
        host.run(f"rm -f {binary}")
    assert result.rc == 0, result
    found = [e for e in events(host, "ssc_exec_tmp", since, success="yes") if binary in e]
    assert found, f"no exec record for {binary}"


@pytest.mark.changes_state
@pytest.mark.parametrize(
    ("as_user", "command", "key"),
    [
        # mkdir and rmdir an empty directory: nothing is left behind.
        (
            "alice",
            "d=/home/alice/.config/systemd/{t} && mkdir $d && rmdir $d",
            "ssc_user_persist",
        ),
        # Open for append and write nothing: the file does not change.
        ("alice", ": >> /home/alice/.bashrc", "ssc_user_persist"),
        ("alice", ": >> /home/alice/.ssh/authorized_keys", "ssc_user_persist"),
        ("root", ": >> /etc/crontab", "ssc_cron"),
        ("root", "d=/etc/systemd/system/{t}.d && mkdir $d && rmdir $d", "ssc_systemd"),
        ("root", ": >> /etc/sudoers", "ssc_sudoers"),
    ],
)
def test_write_to_a_persistence_path_is_recorded(
    host, as_user: str, command: str, key: str
) -> None:
    # What S5 will look for: a new user unit, an rc file or cron change.
    token = f"ssc-audit-{secrets.token_hex(4)}"
    since = now(host)
    with host.sudo(as_user):
        host.check_output(command.format(t=token))
    found = events(host, key, since)
    assert found, f"no {key} record for {command}"
    assert any(f" uid={uid(host, as_user)} " in e for e in found), found


@pytest.mark.changes_state
@pytest.mark.parametrize(
    "setid",
    [
        "chmod u+s {f}",
        "chmod g+s {f}",
        # fchmodat2 (syscall 452), called directly: AT_FDCWD is -100.
        FCHMODAT2,
    ],
)
def test_setting_a_setid_bit_is_recorded(host, setid: str) -> None:
    f = f"/home/alice/ssc-setid-{secrets.token_hex(4)}"
    since = now(host)
    with host.sudo("alice"):
        try:
            host.check_output(f"cp /bin/true {f}")
            host.check_output(setid.format(f=f))
        finally:
            host.run(f"rm -f {f}")
    found = [e for e in events(host, "ssc_suid", since) if f in e]
    assert found, f"no ssc_suid record for {setid}"


@pytest.mark.changes_state
def test_chmod_without_a_setid_bit_is_not_recorded(host) -> None:
    # The mode filter works: a plain chmod is not in the ssc_suid records.
    # A setid chmod right after it is the control: once its record is in the
    # log, the earlier one would be too, and an empty search cannot pass.
    token = secrets.token_hex(4)
    plain, setid = f"/home/alice/ssc-plain-{token}", f"/home/alice/ssc-setid-{token}"
    since = now(host)
    with host.sudo("alice"):
        try:
            host.check_output(f"cp /bin/true {plain} && chmod 0700 {plain}")
            host.check_output(f"cp /bin/true {setid} && chmod u+s {setid}")
        finally:
            host.run(f"rm -f {plain} {setid}")
    found = events(host, "ssc_suid", since)
    assert [e for e in found if setid in e], "control: no record for the setid chmod"
    assert not [e for e in found if plain in e]
