"""Integration test: full pipeline execution against WebGoat.

Prerequisites:
  - WebGoat running at http://localhost:8090/WebGoat
  - Environment variable INTEGRATION_TESTS=1 is set
  - Environment variable WEBGOAT_TESTS=1 is set (opt-in since WebGoat is heavy)

These tests are skipped automatically when WebGoat is not reachable.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from src.core.config import Settings
from src.pipeline import Pipeline


def _webgoat_reachable() -> bool:
    try:
        r = httpx.get("http://localhost:8090/WebGoat", timeout=5)
        return r.status_code < 500
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _webgoat_reachable()
    or not os.getenv("INTEGRATION_TESTS")
    or not os.getenv("WEBGOAT_TESTS"),
    reason="WebGoat not reachable or INTEGRATION_TESTS/WEBGOAT_TESTS env vars not set",
)


@pytest.fixture()
def webgoat_settings(tmp_path: Path) -> Settings:
    return Settings(
        target_url="http://localhost:8090/WebGoat",
        output_dir=str(tmp_path),
        log_level="INFO",
        max_depth=2,
        max_pages=20,
        max_payloads_per_vector=10,
        payload_types="sqli,xss",
        auth_enabled=True,
        auth_url="http://localhost:8090/WebGoat/login",
        auth_username="guest",
        auth_password="guest",
        auth_username_field="username",
        auth_password_field="password",
        auth_success_url="http://localhost:8090/WebGoat/start.mvc",
    )


@pytest.mark.asyncio
async def test_pipeline_finds_vulns_in_webgoat(webgoat_settings: Settings, tmp_path: Path) -> None:
    """End-to-end test: the pipeline must find at least one finding in WebGoat."""
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()

    pipeline = Pipeline(settings=webgoat_settings, scan_dir=scan_dir)
    report = await pipeline.run()

    assert report is not None
    assert report.pages_crawled > 0
    assert report.vectors_found > 0
    assert len(report.findings) > 0

    assert (scan_dir / "report.json").exists()
    assert (scan_dir / "report.html").exists()
    assert (scan_dir / "findings.db").exists()
