"""Unit tests for ReportGenerator."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.analysis.models import (
    Confidence,
    RawFinding,
    ScanReport,
    Severity,
    ValidatedFinding,
)
from src.analysis.report_generator import (
    ReportGenerator,
    _fmt_date,
    _fmt_time,
    _url_host,
    _url_path,
)
from src.core.config import Settings
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_settings(tmp_path: Path) -> Settings:
    return Settings(
        target_url="http://localhost:8080",
        output_dir=str(tmp_path),
        log_level="DEBUG",
    )


def _make_vector() -> AttackVector:
    return AttackVector(
        source_url="http://localhost:8080/login",
        target_url="http://localhost:8080/login",
        method="POST",
        field_name="username",
        surface=SurfaceType.FORM_FIELD,
        field_context="<form><input name='username'>",
        extra_params={},
        priority=1,
        applicable_vulns=[VulnType.SQLI],
    )


def _make_report(scan_dir: Path) -> ScanReport:
    vector = _make_vector()
    raw = RawFinding(
        vector=vector,
        vuln_type=VulnType.SQLI,
        payload="' OR 1=1--",
        response_snippet="you have an error in your SQL syntax",
        confidence=Confidence.CONFIRMED,
        evidence="SQL error pattern matched",
        response_time_ms=120,
        found_at=datetime.utcnow(),
    )
    finding = ValidatedFinding(
        raw=raw,
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        remediation="Use parameterized queries.",
    )
    return ScanReport(
        scan_id="test_scan_001",
        target_url="http://localhost:8080",
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        pages_crawled=5,
        vectors_found=3,
        findings=[finding],
        summary={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
    )


@pytest.mark.asyncio
async def test_json_report_written(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    report = _make_report(tmp_path)
    generator = ReportGenerator(settings, tmp_path)
    await generator.generate(report)

    json_file = tmp_path / "report.json"
    assert json_file.exists()
    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert data["scan_id"] == "test_scan_001"
    assert len(data["findings"]) == 1


@pytest.mark.asyncio
async def test_html_report_written(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    report = _make_report(tmp_path)
    generator = ReportGenerator(settings, tmp_path)
    await generator.generate(report)

    html_file = tmp_path / "report.html"
    assert html_file.exists()
    content = html_file.read_text(encoding="utf-8")
    assert "test_scan_001" in content
    assert "CRITICAL" in content


@pytest.mark.asyncio
async def test_html_iteration2_markup(tmp_path: Path) -> None:
    """Regression: iteration-2 layout (collapsed filters, multi-selects, two-line URL).

    The filters panel must be a ``<details>`` element starting closed (no ``open``
    attribute), the enum filters must use the multi-select pattern, the URL must
    be split into host + path spans, and dates/times must be human-readable.
    """
    settings = _make_settings(tmp_path)
    report = _make_report(tmp_path)
    generator = ReportGenerator(settings, tmp_path)
    await generator.generate(report)

    html = (tmp_path / "report.html").read_text(encoding="utf-8")

    assert '<details class="findings-filters-wrapper">' in html
    assert "<summary>" in html and 'class="summary-counter"' in html
    assert html.count('class="multi-select"') >= 3
    assert 'data-filter-key="severity"' in html
    assert 'data-filter-key="type"' in html
    assert 'data-filter-key="confidence"' in html
    assert 'class="url-host"' in html and 'class="url-path"' in html
    assert 'id="filter-url"' not in html
    assert 'id="filter-remediation"' not in html
    assert "data-url=" not in html
    assert "data-remediation=" not in html


def test_fmt_date_and_time_naive() -> None:
    dt = datetime(2026, 4, 27, 14, 8, 0, 425549)
    assert _fmt_date(dt) == "27-04-2026"
    assert _fmt_time(dt) == "14:08 UTC"


def test_fmt_time_aware_offset() -> None:
    dt = datetime(2026, 4, 27, 14, 8, tzinfo=timezone(timedelta(hours=2)))
    # +0200 → "UTC+02:00"
    assert _fmt_time(dt) == "14:08 UTC+02:00"


def test_url_host_and_path_split() -> None:
    url = "http://dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
    assert _url_host(url) == "http://dvwa"
    assert _url_path(url) == "/vulnerabilities/sqli/?id=1&Submit=Submit"
    # URL without scheme/netloc round-trips safely.
    assert _url_host("/just/a/path") == "/just/a/path"
    assert _url_path("/just/a/path") == ""


@pytest.mark.asyncio
async def test_sqlite_report_written(tmp_path: Path) -> None:
    import aiosqlite

    settings = _make_settings(tmp_path)
    report = _make_report(tmp_path)
    generator = ReportGenerator(settings, tmp_path)
    await generator.generate(report)

    db_file = tmp_path / "findings.db"
    assert db_file.exists()

    async with aiosqlite.connect(db_file) as db:
        async with db.execute("SELECT COUNT(*) FROM findings") as cursor:
            row = await cursor.fetchone()
            assert row is not None and row[0] == 1

        async with db.execute(
            "SELECT scan_id FROM scan_metadata WHERE scan_id = ?", ("test_scan_001",)
        ) as cursor:
            row = await cursor.fetchone()
            assert row is not None


@pytest.mark.asyncio
async def test_html_summary_cards_match_finding_counts(tmp_path: Path) -> None:
    """Regression: summary card counts must match the number of findings.

    The pipeline builds the summary dict with lowercase keys (``Severity.value``),
    but earlier versions of the templates looked up uppercase keys and always
    got the default 0 — rendering "Findings (40)" alongside five cards showing
    0 / 0 / 0 / 0 / 0.
    """
    settings = _make_settings(tmp_path)
    vector = _make_vector()
    raw = RawFinding(
        vector=vector,
        vuln_type=VulnType.XSS,
        payload="<img src=x onerror=alert(1)>",
        response_snippet="reflected",
        confidence=Confidence.LIKELY,
        evidence="payload reflected",
        response_time_ms=50,
        found_at=datetime.utcnow(),
    )
    findings = [
        ValidatedFinding(raw=raw, severity=Severity.MEDIUM, cvss_score=6.1) for _ in range(3)
    ]
    report = ScanReport(
        scan_id="summary_regression",
        target_url="http://localhost:8080",
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        pages_crawled=1,
        vectors_found=1,
        findings=findings,
        summary={"critical": 0, "high": 0, "medium": 3, "low": 0, "info": 0},
    )
    generator = ReportGenerator(settings, tmp_path)
    await generator.generate(report)

    html = (tmp_path / "report.html").read_text(encoding="utf-8")

    # The MEDIUM card must show the real count of 3, not the default 0.
    assert '<div class="card MEDIUM">\n          <div class="count">3</div>' in html
    # The CRITICAL card must still show 0 (no critical findings).
    assert '<div class="card CRITICAL">\n          <div class="count">0</div>' in html


@pytest.mark.asyncio
async def test_report_with_no_findings(tmp_path: Path) -> None:
    settings = _make_settings(tmp_path)
    report = ScanReport(
        scan_id="empty_scan",
        target_url="http://localhost:8080",
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        pages_crawled=0,
        vectors_found=0,
        findings=[],
        summary={},
    )
    generator = ReportGenerator(settings, tmp_path)
    await generator.generate(report)

    json_file = tmp_path / "report.json"
    assert json_file.exists()
    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert data["findings"] == []
