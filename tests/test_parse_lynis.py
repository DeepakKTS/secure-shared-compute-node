"""Unit tests for scripts/parse_lynis.py. The fixture is synthetic; real
reports stay in .lab/ (gitignored)."""

import json
import re
from pathlib import Path

import parse_lynis as pl
import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "lynis-report.dat"
TEXT = FIXTURE.read_text()
SHA = "0123456789abcdef0123456789abcdef01234567"


def without(key: str) -> str:
    return "\n".join(line for line in TEXT.splitlines() if not line.startswith(f"{key}="))


def replace(key: str, value: str) -> str:
    return "\n".join(
        f"{key}={value}" if line.startswith(f"{key}=") else line for line in TEXT.splitlines()
    )


def test_summary_has_the_evidence_schema() -> None:
    assert pl.summarize(TEXT, "before", SHA) == {
        "label": "before",
        "host": "ssc-node",
        "timestamp": "2026-01-02T03:04:05Z",
        "lynis_version": "3.1.7",
        "hardening_index": 42,
        "warnings": 2,
        "suggestions": 3,
        "git_sha": SHA,
    }


def test_schema_keys_match_docs_evidence_md() -> None:
    doc = (ROOT / "docs" / "EVIDENCE.md").read_text()
    example = doc.split("`results/lynis-<label>.json`")[1].split("```json")[1].split("```")[0]
    assert set(pl.summarize(TEXT, "after", SHA)) == set(json.loads(example))


def test_no_warnings_or_suggestions_counts_zero() -> None:
    text = "\n".join(
        line for line in TEXT.splitlines() if not line.startswith(("warning[]", "suggestion[]"))
    )
    summary = pl.summarize(text, "after", SHA)
    assert (summary["warnings"], summary["suggestions"]) == (0, 0)


@pytest.mark.parametrize("key", list(pl.REQUIRED))
def test_missing_required_field_is_refused(key: str) -> None:
    with pytest.raises(pl.ReportError, match=key):
        pl.summarize(without(key), "before", SHA)


@pytest.mark.parametrize("value", ["", "abc", "-1", "101", "61.5", " 42"])
def test_bad_hardening_index_is_refused(value: str) -> None:
    with pytest.raises(pl.ReportError):
        pl.summarize(replace("hardening_index", value), "before", SHA)


def test_bad_start_time_is_refused() -> None:
    with pytest.raises(pl.ReportError, match="not a date"):
        pl.summarize(replace("report_datetime_start", "yesterday"), "before", SHA)


def test_repeated_plain_keys_are_kept_in_order() -> None:
    values, _ = pl.parse_report(TEXT)
    assert values["uncommon_network_protocol_enabled"] == ["dccp", "sctp"]


@pytest.mark.parametrize("key", list(pl.REQUIRED))
def test_required_field_twice_is_refused_even_with_the_same_value(key: str) -> None:
    value = next(line for line in TEXT.splitlines() if line.startswith(f"{key}="))
    with pytest.raises(pl.ReportError, match=rf"repeats {key} \(2 times\)"):
        pl.summarize(f"{TEXT}\n{value}\n", "before", SHA)


def test_line_without_equals_is_refused() -> None:
    with pytest.raises(pl.ReportError, match="not key=value"):
        pl.summarize(TEXT + "\ngarbage line\n", "before", SHA)


def test_unknown_label_is_refused() -> None:
    with pytest.raises(pl.ReportError, match="label"):
        pl.summarize(TEXT, "during", SHA)


def run(tmp_path: Path, *extra: str, report: Path = FIXTURE) -> tuple[int, Path]:
    out = tmp_path / "results" / "lynis-before.json"
    code = pl.main([str(report), "--label", "before", "--out", str(out), "--git-sha", SHA, *extra])
    return code, out


def test_cli_writes_sorted_json_and_reruns_without_diff(tmp_path: Path) -> None:
    code, out = run(tmp_path)
    assert code == 0
    first = out.read_bytes()
    assert first.endswith(b"\n")
    data = json.loads(first)
    assert list(data) == sorted(data)
    assert data["hardening_index"] == 42
    assert run(tmp_path)[0] == 0
    assert out.read_bytes() == first
    assert list(out.parent.iterdir()) == [out], "no temp file left behind"


def test_cli_fails_closed_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = tmp_path / "broken.dat"
    broken.write_text(without("hardening_index"))
    code, out = run(tmp_path, report=broken)
    assert code == 1
    assert "hardening_index" in capsys.readouterr().err
    assert not out.exists()


def test_cli_missing_report_fails(tmp_path: Path) -> None:
    code, out = run(tmp_path, report=tmp_path / "absent.dat")
    assert code == 1
    assert not out.exists()


def test_cli_rejects_unknown_label(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        pl.main([str(FIXTURE), "--label", "during", "--out", str(tmp_path / "x.json")])


def test_default_git_sha_is_head_and_marks_uncommitted_code() -> None:
    sha = pl.head_sha()
    assert re.fullmatch(r"[0-9a-f]{40}(-dirty)?", sha), sha
    assert sha.startswith(pl.git("rev-parse", "HEAD"))


def test_dirty_suffix_follows_git_status(monkeypatch: pytest.MonkeyPatch) -> None:
    head = "0" * 40
    for status, expected in (("", head), (" M scripts/parse_lynis.py", f"{head}-dirty")):
        answers = {"rev-parse": head, "status": status}
        monkeypatch.setattr(pl, "git", lambda *args, a=answers: a[args[0]])
        assert pl.head_sha() == expected
