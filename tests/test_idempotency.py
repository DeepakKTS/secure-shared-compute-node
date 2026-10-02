"""Unit tests for scripts/idempotency.py (make idempotency, F-28). No VMs:
a fake runner returns canned ansible-playbook output."""

import io

import idempotency

STARS = "*" * 40


def recap_line(host: str, changed: int = 0, unreachable: int = 0, failed: int = 0) -> str:
    return (
        f"{host:<26} : ok=20   changed={changed:<4} unreachable={unreachable:<4}"
        f" failed={failed:<4} skipped=3    rescued=0    ignored=0"
    )


def output(*recap: str, tasks: tuple[str, ...] = ()) -> list[str]:
    return [
        f"PLAY [Base settings on every lab VM] {STARS}",
        "",
        f"TASK [base : Install the base packages] {STARS}",
        "ok: [ssc-node]",
        "ok: [ssc-monitor]",
        *tasks,
        "",
        f"PLAY RECAP {STARS}",
        *recap,
    ]


CLEAN = output(recap_line("ssc-attacker"), recap_line("ssc-monitor"), recap_line("ssc-node"))
CHANGED = output(
    recap_line("ssc-attacker"),
    recap_line("ssc-monitor"),
    recap_line("ssc-node", changed=2),
    tasks=(
        f"TASK [base : Write the sysctl hardening file] {STARS}",
        "changed: [ssc-node]",
        "ok: [ssc-monitor]",
        f"RUNNING HANDLER [base : Apply sysctl settings] {STARS}",
        "changed: [ssc-node]",
    ),
)


class FakeRuns:
    def __init__(self, *runs: tuple[int, list[str]]):
        self.runs = list(runs)
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> tuple[int, list[str]]:
        self.calls.append(argv)
        return self.runs.pop(0)


def check(runs: FakeRuns, extra: tuple[str, ...] = ()) -> tuple[int, str]:
    out = io.StringIO()
    code = idempotency.check(list(extra), runner=runs, out=out)
    return code, out.getvalue()


def test_recap_reads_each_host() -> None:
    hosts = idempotency.recap(CHANGED)
    assert [(h.host, h.ok, h.changed, h.unreachable, h.failed) for h in hosts] == [
        ("ssc-attacker", 20, 0, 0, 0),
        ("ssc-monitor", 20, 0, 0, 0),
        ("ssc-node", 20, 2, 0, 0),
    ]


def test_recap_reads_only_lines_after_the_recap_header() -> None:
    # A task's output that looks like a recap line does not count.
    lines = [recap_line("ssc-node", changed=0), *CHANGED]
    assert [h.changed for h in idempotency.recap(lines) if h.host == "ssc-node"] == [2]


def test_recap_ignores_color_codes() -> None:
    lines = [f"\x1b[0;33m{line}\x1b[0m" for line in CHANGED]
    assert [h.changed for h in idempotency.recap(lines)] == [0, 0, 2]
    first = idempotency.changed_tasks(lines)[0]
    assert first == ("ssc-node", "base : Write the sysctl hardening file")


def test_changed_tasks_names_tasks_and_handlers() -> None:
    assert idempotency.changed_tasks(CHANGED) == [
        ("ssc-node", "base : Write the sysctl hardening file"),
        ("ssc-node", "base : Apply sysctl settings"),
    ]


def test_two_clean_runs_pass() -> None:
    runs = FakeRuns((0, CLEAN), (0, CLEAN))
    code, text = check(runs)
    assert code == 0, text
    assert runs.calls == [[".venv/bin/ansible-playbook", "playbooks/harden.yml"]] * 2
    assert "idempotency: PASS, the second run changed nothing" in text
    assert "  ssc-node       changed=0 unreachable=0 failed=0" in text.splitlines()


def test_options_go_to_both_runs() -> None:
    runs = FakeRuns((0, CLEAN), (0, CLEAN))
    check(runs, ("--tags", "base"))
    assert (
        runs.calls == [[".venv/bin/ansible-playbook", "playbooks/harden.yml", "--tags", "base"]] * 2
    )


def test_a_change_on_the_second_run_fails_and_names_the_task() -> None:
    code, text = check(FakeRuns((0, CHANGED), (0, CHANGED)))
    assert code == 1
    assert "  ssc-node       changed=2 unreachable=0 failed=0" in text.splitlines()
    assert "  changed on the second run: ssc-node: base : Write the sysctl hardening file" in text
    assert "  changed on the second run: ssc-node: base : Apply sysctl settings" in text
    assert text.splitlines()[-1].startswith("idempotency: FAIL")


def test_changes_on_the_first_run_only_pass() -> None:
    code, text = check(FakeRuns((0, CHANGED), (0, CLEAN)))
    assert code == 0, text


def test_a_failed_first_run_stops_before_the_second() -> None:
    runs = FakeRuns((2, CLEAN), (0, CLEAN))
    code, text = check(runs)
    assert code == 1
    assert len(runs.calls) == 1
    assert "idempotency: FAIL, the first run exited 2" in text


def test_a_failed_second_run_fails() -> None:
    code, text = check(FakeRuns((0, CLEAN), (4, CLEAN)))
    assert code == 1
    assert "idempotency: FAIL, the second run exited 4" in text


def test_an_unreachable_or_failed_host_fails() -> None:
    for bad in (recap_line("ssc-node", unreachable=1), recap_line("ssc-node", failed=1)):
        second = output(recap_line("ssc-monitor"), bad)
        code, text = check(FakeRuns((0, CLEAN), (0, second)))
        assert code == 1, bad
        assert text.splitlines()[-1].startswith("idempotency: FAIL")


def test_a_run_with_no_host_fails() -> None:
    # An empty inventory: ansible-playbook exits 0 and prints no host.
    empty = ["[WARNING]: provided hosts list is empty", f"PLAY RECAP {STARS}"]
    code, text = check(FakeRuns((0, empty), (0, empty)))
    assert code == 1
    assert "no PLAY RECAP with a host" in text
