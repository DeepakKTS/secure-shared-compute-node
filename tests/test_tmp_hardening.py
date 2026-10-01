"""State tests for roles/tmp_hardening on the node (F-26). They need the lab:
run `make verify`, or `pytest -m lab tests/test_tmp_hardening.py` with
.venv/bin on PATH.
"""

import re

import lab_hosts
import pytest

pytestmark = pytest.mark.lab
testinfra_hosts = lab_hosts.hosts("node")

UNITS = {"k": 1024, "M": 1024**2, "G": 1024**3}
HARDENED = {"nosuid", "nodev", "noexec"}


def options(host, path: str) -> set[str]:
    return set(host.check_output(f"findmnt -no OPTIONS --mountpoint {path}").split(","))


def size_bytes(value: str) -> int:
    match = re.fullmatch(r"(\d+)([kMG]?)", value)
    assert match, f"size must be a number with k, M or G: {value}"
    return int(match.group(1)) * UNITS.get(match.group(2), 1)


def test_tmp_is_its_own_tmpfs(host) -> None:
    assert host.check_output("findmnt -no FSTYPE --mountpoint /tmp") == "tmpfs"
    assert HARDENED <= options(host, "/tmp")
    assert host.file("/tmp").mode == 0o1777


def test_tmp_size_comes_from_group_vars(host) -> None:
    # A capped tmpfs: filling /tmp fills /tmp, not the root disk.
    want = size_bytes(str(host.ansible.get_variables()["tmp_hardening_tmp_size"]))
    assert int(host.check_output("df -B1 --output=size /tmp | tail -1")) == want


def test_dev_shm_is_hardened(host) -> None:
    assert HARDENED <= options(host, "/dev/shm")


@pytest.mark.parametrize("path", ["/tmp", "/dev/shm"])
def test_fstab_holds_the_options_for_boot(host, path: str) -> None:
    fields = host.check_output(f"findmnt --fstab -no OPTIONS {path}")
    assert HARDENED <= set(fields.split(",")), fields


@pytest.mark.parametrize("path", ["/tmp", "/dev/shm"])
def test_user_cannot_run_a_binary_from(host, path: str) -> None:
    # What a dropper does: write a binary to a world-writable path and run it.
    # (noexec does not stop `sh file` or `python3 file`; see the role README.)
    binary = f"{path}/ssc-noexec-check"
    with host.sudo("alice"):
        host.check_output(f"cp /bin/true {binary} && chmod 0755 {binary}")
        result = host.run(binary)
        host.run(f"rm -f {binary}")
    assert result.rc == 126, result
    assert "Permission denied" in result.stderr


def test_apt_preconfigure_runs_config_scripts_outside_tmp(host) -> None:
    # apt runs dpkg-preconfigure before it unpacks packages. If debconf ever
    # extracted config scripts to /tmp again, noexec would stop them. Build a
    # small package with a config script and check where it ran from.
    with host.sudo():
        work = host.check_output("mktemp -d -p /root ssc-preconf.XXXXXX")
        assert re.fullmatch(r"/root/ssc-preconf\.\w{6}", work), work
        try:
            host.check_output(
                "mkdir -p %s/pkg/DEBIAN && cd %s/pkg/DEBIAN"
                " && printf 'Package: ssc-preconf-check\\nVersion: 1.0\\nArchitecture: all\\n"
                "Maintainer: lab <lab@localhost>\\nDescription: lab check\\n' > control"
                " && printf 'Template: ssc-preconf-check/q\\nType: boolean\\nDefault: true\\n"
                "Description: q\\n' > templates"
                " && printf '#!/bin/sh\\necho \"$0\" >> %s/ran\\n' > config && chmod 0755 config"
                " && dpkg-deb --build --root-owner-group %s/pkg %s/check.deb",
                *([work] * 5),
            )
            out = host.run(
                "DEBIAN_FRONTEND=noninteractive dpkg-preconfigure %s/check.deb", f"{work}"
            )
            ran = host.run("cat %s/ran", work).stdout.split()
        finally:
            host.run("rm -r -- %s", work)
    assert "Can't exec" not in out.stdout + out.stderr, out
    assert len(ran) == 1 and not ran[0].startswith("/tmp/"), ran
