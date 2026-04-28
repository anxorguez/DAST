"""Shared pytest fixtures for the DAST test suite."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import Confidence, RawFinding, Severity, ValidatedFinding
from src.core.config import Settings
from src.vectors.models import (
    AttackVector,
    CrawledPage,
    FormField,
    HTMLForm,
    SurfaceType,
    VulnType,
)

# ---------------------------------------------------------------------------
# Event-loop (pytest-asyncio)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def event_loop_policy():
    return asyncio.DefaultEventLoopPolicy()


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        target_url="http://localhost:8080",
        output_dir="/tmp/dast-test-reports",
        log_level="DEBUG",
        max_depth=2,
        max_pages=10,
        max_payloads_per_vector=5,
        payload_types="sqli,xss,cmdi",
    )


# ---------------------------------------------------------------------------
# HTTP Client mock
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_http_client() -> MagicMock:
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    response = MagicMock()
    response.status_code = 200
    response.text = "<html><body>OK</body></html>"
    response.elapsed.total_seconds.return_value = 0.1
    client.get = AsyncMock(return_value=response)
    client.post = AsyncMock(return_value=response)
    client.get_no_retry = AsyncMock(return_value=response)
    client.post_no_retry = AsyncMock(return_value=response)
    return client


# ---------------------------------------------------------------------------
# Model fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_form_field() -> FormField:
    return FormField(name="username", field_type="text", default_value="")


@pytest.fixture()
def sample_html_form(sample_form_field: FormField) -> HTMLForm:
    return HTMLForm(
        action_url="http://localhost:8080/login",
        method="POST",
        fields=[
            sample_form_field,
            FormField(name="password", field_type="password", default_value=""),
        ],
    )


@pytest.fixture()
def sample_crawled_page(sample_html_form: HTMLForm) -> CrawledPage:
    return CrawledPage(
        url="http://localhost:8080/login",
        html="<html><body><form method='POST' action='/login'>"
        "<input name='username'><input name='password' type='password'>"
        "<input type='submit'></form></body></html>",
        forms=[sample_html_form],
        links=["http://localhost:8080/about"],
        status_code=200,
        crawled_at=datetime.utcnow(),
    )


@pytest.fixture()
def sample_attack_vector() -> AttackVector:
    return AttackVector(
        target_url="http://localhost:8080/login",
        method="POST",
        field_name="username",
        surface_type=SurfaceType.FORM_FIELD,
        extra_fields={"password": ""},
        priority=1,
        vuln_types=[VulnType.SQLI, VulnType.XSS],
    )


@pytest.fixture()
def sample_raw_finding(sample_attack_vector: AttackVector) -> RawFinding:
    return RawFinding(
        vector=sample_attack_vector,
        vuln_type=VulnType.SQLI,
        payload="' OR 1=1--",
        response_snippet="you have an error in your SQL syntax",
        confidence=Confidence.CONFIRMED,
        evidence="SQL error pattern matched: 'you have an error in your SQL syntax'",
        response_time_ms=150,
        found_at=datetime.utcnow(),
    )


@pytest.fixture()
def sample_validated_finding(sample_raw_finding: RawFinding) -> ValidatedFinding:
    return ValidatedFinding(
        raw=sample_raw_finding,
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        remediation="Use parameterized queries / prepared statements.",
    )


# ---------------------------------------------------------------------------
# Temporary payload directory
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_payload_dir(tmp_path: Path) -> Path:
    """Create a temporary payloads directory tree with minimal payload files."""
    for vuln in ("sqli", "xss", "cmdi"):
        d = tmp_path / vuln
        d.mkdir()
        (d / "sample.txt").write_text(
            "# comment\n\npayload_one\npayload_two\npayload_three\n",
            encoding="utf-8",
        )
    return tmp_path
