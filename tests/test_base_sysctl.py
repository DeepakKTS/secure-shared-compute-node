"""Unit tests for roles/base's kernel settings file, with no VM. They render
templates/sysctl-hardening.conf.j2 the way Ansible does (Jinja2 with
trim_blocks) and check what systemd-sysctl would read from it.
"""

from pathlib import Path

import jinja2
import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "roles" / "base"
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
FORWARDING = ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"]


def settings() -> list[tuple[str, str]]:
    env = jinja2.Environment(
        trim_blocks=True, keep_trailing_newline=True, undefined=jinja2.StrictUndefined
    )
    template = env.from_string((ROLE / "templates" / "sysctl-hardening.conf.j2").read_text())
    text = template.render(**DEFAULTS)
    pairs = []
    for line in text.splitlines():
        if line.strip() and not line.startswith("#"):
            key, sep, value = line.partition(" = ")
            assert sep, f"not a sysctl line: {line!r}"
            pairs.append((key, value))
    return pairs


def test_every_default_is_written_once() -> None:
    keys = [key for key, _ in settings()]
    for key, value in DEFAULTS["base_sysctl"].items():
        assert keys.count(key) == 1, key
        assert (key, str(value)) in settings(), key


def test_forwarding_is_pinned_off() -> None:
    # The kernel default is 0. Pinning it means a vendor sysctl.d file that
    # turns it on is overridden at boot (this file applies last).
    for key in FORWARDING:
        assert DEFAULTS["base_sysctl"][key] == 0, key
        assert (key, "0") in settings(), key


def test_forwarding_comes_before_the_redirect_settings() -> None:
    # A change of net.ipv4.ip_forward makes the kernel reset
    # net.ipv4.conf.all.accept_redirects (to 1 when forwarding goes off), so
    # forwarding must be set first or it would undo the 0 written above it.
    keys = [key for key, _ in settings()]
    last_forwarding = max(keys.index(key) for key in FORWARDING)
    redirects = [i for i, key in enumerate(keys) if "redirects" in key]
    assert redirects, "no redirect settings rendered"
    assert last_forwarding < min(redirects), keys
