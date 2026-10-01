"""State tests for roles/fail2ban on the node and the monitor (F-24). They need
the lab: run `make verify`, or `pytest -m lab tests/test_fail2ban.py` with
.venv/bin on PATH. The S1 rehearsal makes refused logins from ssc-attacker, a
lab host in the inventory, and lifts the ban afterwards.
"""

import re
import subprocess
import time
from pathlib import Path

import lab_hosts
import pytest
import testinfra

pytestmark = pytest.mark.lab
testinfra_hosts = lab_hosts.hosts("node", "monitor")

LAB = Path(__file__).resolve().parent.parent / ".lab"
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
# A user name that exists nowhere: sshd logs "Invalid user", which the sshd
# filter counts in its default (normal) mode.
S1_USER = "ssc-s1-nouser"


def variables(host) -> dict:
    return host.ansible.get_variables()


def seconds(value) -> int:
    """fail2ban time from group_vars ("10m", "1h", or plain seconds)."""
    match = re.fullmatch(r"(\d+)([smhd]?)", str(value))
    assert match, value
    return int(match.group(1)) * UNIT_SECONDS.get(match.group(2) or "s", 1)


def client(host, *args: str) -> str:
    with host.sudo():
        return host.check_output("fail2ban-client " + " ".join(args))


def listed(output: str) -> list[str]:
    """Items of fail2ban-client's tree output ("|- x" and "`- x" lines)."""
    return re.findall(r"^\s*[|`]- (\S+)\s*$", output, re.MULTILINE)


def banned(host) -> list[str]:
    return client(host, "get sshd banip").split()


def total_failed(host) -> int:
    return int(re.search(r"Total failed:\s+(\d+)", client(host, "status sshd")).group(1))


def attacker():
    return testinfra.get_host("ansible://ssc-attacker")


def ssh_port_answers(target: str) -> bool:
    """A TCP connect from the attacker to port 22 succeeds."""
    result = attacker().run(f"timeout 3 bash -c 'echo > /dev/tcp/{target}/22' 2>/dev/null")
    return result.rc == 0


def wait_for_ban(host, address: str, timeout: float = 30) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if address in banned(host):
            return True
        time.sleep(1)
    return False


def test_fail2ban_runs_at_boot(host) -> None:
    assert host.service("fail2ban").is_enabled
    assert host.run("systemctl is-active fail2ban").stdout.strip() == "active"


def test_sshd_jail_reads_the_journal_of_ssh_service(host) -> None:
    # The `systemd` backend is the only one with journal matches. The match
    # is on the unit, which journald sets itself; see the forged-line test.
    status = client(host, "status sshd")
    assert re.search(r"Journal matches:\s+_SYSTEMD_UNIT=ssh\.service\s*$", status, re.M), status


def test_sshd_jail_bans_with_nftables_multiport(host) -> None:
    # Ask the running jail for the action itself. `get sshd actions` says
    # "No actions" in 1.0.2 even when it has one, and a jail whose action was
    # lost in a reload still logs "Ban" while blocking nothing.
    actionban = client(host, "get sshd action nftables-multiport actionban")
    assert "nft add element inet f2b-table" in actionban, actionban
    assert client(host, "get sshd action nftables-multiport blocktype").strip() == "reject"


def test_sshd_jail_limits_come_from_group_vars(host) -> None:
    v = variables(host)
    assert client(host, "get sshd maxretry").strip() == str(v["fail2ban_maxretry"])
    assert int(client(host, "get sshd findtime")) == seconds(v["fail2ban_findtime"])
    assert int(client(host, "get sshd bantime")) == seconds(v["fail2ban_bantime"])


def test_controller_and_monitor_are_ignored_attacker_is_not(host) -> None:
    v = variables(host)
    ignored = listed(client(host, "get sshd ignoreip"))
    assert v["lab_controller_ip"] in ignored, ignored
    for name in v["groups"]["monitor"]:
        assert lab_hosts.address(name) in ignored, ignored
    assert lab_hosts.address("ssc-attacker") not in ignored, ignored


@pytest.mark.changes_state
@pytest.mark.usefixtures("attacker_unbanned")
def test_local_user_cannot_forge_sshd_lines(host) -> None:
    # Any local user can name their process "sshd" and write to syslog. The
    # sshd filter's stock journal match accepts `_COMM=sshd`, so such lines
    # would count and let a user get any address banned. The role matches on
    # `_SYSTEMD_UNIT=ssh.service` instead, which a user process cannot have.
    target = lab_hosts.address("ssc-attacker")
    forger = (
        "import ctypes, syslog, time; ctypes.CDLL(None).prctl(15, b'sshd', 0, 0, 0); "
        "syslog.openlog('sshd', syslog.LOG_PID, syslog.LOG_AUTH); "
        f"[syslog.syslog('Invalid user ssc-forged from {target} port 22') for _ in range(6)]; "
        "time.sleep(1)"
    )
    before = total_failed(host)
    since = host.check_output("date +%s")
    with host.sudo("nobody"):
        host.check_output("python3 -c %s", forger)
    time.sleep(5)
    with host.sudo():
        as_sshd = host.check_output(f"journalctl _COMM=sshd --since @{since} -o cat")
        in_unit = host.check_output(f"journalctl _SYSTEMD_UNIT=ssh.service --since @{since} -o cat")
    # The forged lines did reach the journal under the name sshd, so the
    # check below is not empty.
    assert as_sshd.count("ssc-forged") == 6, as_sshd
    assert "ssc-forged" not in in_unit
    assert total_failed(host) == before
    assert target not in banned(host)


@pytest.mark.changes_state
@pytest.mark.usefixtures("attacker_unbanned")
def test_s1_rehearsal_bans_the_attacker_and_blocks_it(host) -> None:
    # What scenario S1 (P6.4) will do: logins as a user that does not exist,
    # from the attacker, until fail2ban bans it.
    v = variables(host)
    target = v["ansible_host"]
    source = lab_hosts.address("ssc-attacker")
    assert ssh_port_answers(target), "attacker cannot reach SSH before the test"
    since = host.check_output("date +%s")
    for _ in range(int(v["fail2ban_maxretry"])):
        attacker().run(
            "ssh -o BatchMode=yes -o ConnectTimeout=5 -o PubkeyAuthentication=no "
            "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"{S1_USER}@{target} true 2>&1; true"
        )
    assert wait_for_ban(host, source), client(host, "status sshd")

    # fail2ban-regex matches every S1 line sshd wrote, and nothing else is fed
    # to it (other lines, such as "Accepted" from the controller, also count
    # as hits). Earlier refused logins from the attacker count toward the
    # ban too, so it can come before the last try.
    s1_line = f"Invalid user {S1_USER} from {source} "
    with host.sudo():
        report = host.check_output(
            "f=$(mktemp) && journalctl _SYSTEMD_UNIT=ssh.service --since @%s -o short-iso"
            " | grep -F %s > $f; fail2ban-regex $f sshd; rc=$?; rm -f $f; exit $rc",
            since,
            s1_line,
        )
    tries = int(re.search(r"^Lines: (\d+) lines", report, re.M).group(1))
    matched = int(re.search(r"^Failregex: (\d+) total", report, re.M).group(1))
    assert tries >= 1 and matched == tries, report

    # The ban lives in fail2ban's own nftables table, and the next connection
    # from the attacker is refused there.
    with host.sudo():
        assert source in host.check_output("nft list set inet f2b-table addr-set-sshd")
    assert not ssh_port_answers(target)

    # Reloading the firewall replaces only its own table, so the ban stays.
    with host.sudo():
        host.check_output("systemctl reload nftables")
        assert source in host.check_output("nft list set inet f2b-table addr-set-sshd")
    assert not ssh_port_answers(target)

    # The controller is still let in over a new connection.
    result = subprocess.run(
        ["ssh", "-F", str(LAB / "ssh_config"), "-o", "ControlPath=none", "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10", v["inventory_hostname"], "sudo -n true"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr

    # Lifting the ban opens SSH to the attacker again.
    lab_hosts.unban_attacker(host)
    assert ssh_port_answers(target)
