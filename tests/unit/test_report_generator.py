"""Unit tests for ReportGenerator."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from src.analysis.models import (
    Confidence,
    RawFinding,
    ScanReport,
    Severity,
    ValidatedFinding,
)
from src.analysis.report_generator import ReportGenerator
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
        summary={"CRITICAL": 1},
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
