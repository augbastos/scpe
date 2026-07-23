import json
from pathlib import Path

import pytest

from scpe.analyze import SYSTEM_ANALYZE, analyze
from scpe.backends import MockBackend
from scpe.contribute import ContributeError

TWO_ISSUES = json.dumps({"issues": [
    {"title": "add() subtracts", "rationale": "planted bug", "files": ["demo/calc.py"]},
    {"title": "no zero-division guard", "rationale": "unhandled edge", "files": ["demo/calc.py"]},
]})


def _mock(grade_summary: str = "solid work") -> MockBackend:
    return MockBackend({
        "ANALYZE": TWO_ISSUES,
        "GRADE": json.dumps({"grade": "B", "summary": grade_summary}),
    })


def test_analyze_returns_issues_and_grade(fixture_repo: Path, tmp_path: Path):
    report = analyze(str(fixture_repo), _mock(), workdir=tmp_path / "w")
    assert len(report["issues"]) == 2
    assert report["issues"][0]["title"] == "add() subtracts"
    assert report["grade"] == "B"
    assert report["summary"] == "solid work"
    assert len(report["base_sha"]) == 40
    assert report["backend"] == "mock"
    assert report["repo"] == str(fixture_repo)


def test_analyze_tolerates_numeric_grade(fixture_repo: Path, tmp_path: Path):
    mock = MockBackend({
        "ANALYZE": TWO_ISSUES,
        "GRADE": json.dumps({"grade": 82, "summary": "good"}),
    })
    report = analyze(str(fixture_repo), mock, workdir=tmp_path / "w")
    assert report["grade"] == 82


def test_analyze_scrubs_summary(fixture_repo: Path, tmp_path: Path):
    leaky = "otherwise clean, but leaked sk-abcdefgh1234567890ABCD in a comment"
    report = analyze(str(fixture_repo), _mock(grade_summary=leaky), workdir=tmp_path / "w")
    assert "sk-abcdefgh1234567890ABCD" not in report["summary"]
    assert "[REDACTED]" in report["summary"]


def test_analyze_empty_issues_is_a_clean_report_not_an_error(fixture_repo: Path, tmp_path: Path):
    """Zero issues is a POSITIVE result (the repo looks clean) — analyze() must return a
    normal report with an empty issues list, never raise. This is the prerequisite for
    `attest` ever emitting a "clean" verdict end-to-end."""
    mock = MockBackend({
        "ANALYZE": json.dumps({"issues": []}),
        "GRADE": json.dumps({"grade": "A", "summary": "nothing to flag"}),
    })
    report = analyze(str(fixture_repo), mock, workdir=tmp_path / "w")
    assert report["issues"] == []
    assert report["grade"] == "A"
    assert report["summary"] == "nothing to flag"
    assert report["repo"] == str(fixture_repo)


def test_analyze_unparseable_analysis_raises(fixture_repo: Path, tmp_path: Path):
    mock = MockBackend({
        "ANALYZE": "no json here at all",
        "GRADE": json.dumps({"grade": "C", "summary": "x"}),
    })
    with pytest.raises(ContributeError):
        analyze(str(fixture_repo), mock, workdir=tmp_path / "w")


def test_system_prompt_grades_and_briefs_only():
    assert "Grade and brief" in SYSTEM_ANALYZE
    assert "do not fix" in SYSTEM_ANALYZE
