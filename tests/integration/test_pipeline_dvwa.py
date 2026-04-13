"""Integration test: full pipeline execution against DVWA.

Prerequisites (satisfied by GitHub Actions test workflow or start.sh):
  - DVWA running at http://localhost:8080
  - Security level set to 'low'
  - Environment variable INTEGRATION_TESTS=1 is set

These tests are skipped automatically when DVWA is not reachable.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from src.analysis.models import Severity
from src.core.config import Settings
from src.pipeline import Pipeline


def _dvwa_reachable() -> bool:
    try:
        r = httpx.get("http://localhost:8080", timeout=5)
        return r.status_code < 500
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _dvwa_reachable() or not os.getenv("INTEGRATION_TESTS"),
    reason="DVWA not reachable or INTEGRATION_TESTS env var not set",
)


@pytest.fixture()
def dvwa_settings(tmp_path: Path) -> Settings:
    return Settings(
        target_url="http://localhost:8080",
        scan_profile="default",
        output_dir=str(tmp_path),
        log_level="INFO",
        max_depth=2,
        max_pages=30,
        max_payloads_per_vector=10,
        payload_types="sqli,xss",
        auth_enabled=True,
        auth_url="http://localhost:8080/login.php",
        auth_username="admin",
        auth_password="password",
        auth_username_field="username",
        auth_password_field="password",
        auth_success_url="http://localhost:8080/index.php",
        dvwa_security_level="low",
        dvwa_username="admin",
        dvwa_password="password",
    )


@pytest.mark.asyncio
async def test_pipeline_finds_vulns_in_dvwa(dvwa_settings: Settings, tmp_path: Path) -> None:
    """End-to-end test: the pipeline must find at least one HIGH or CRITICAL finding in DVWA."""
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()

    pipeline = Pipeline(settings=dvwa_settings, scan_dir=scan_dir)
    report = await pipeline.run()

    assert report is not None
    assert report.pages_crawled > 0
    assert report.vectors_found > 0

    severe_findings = [
        f for f in report.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    assert len(severe_findings) > 0, (
        f"Expected at least one HIGH/CRITICAL finding in DVWA. "
        f"Got findings: {[(f.raw.vuln_type.value, f.severity.value) for f in report.findings]}"
    )

    # Reports must be written to disk
    assert (scan_dir / "report.json").exists()
    assert (scan_dir / "report.html").exists()
    assert (scan_dir / "findings.db").exists()
