"""Unit tests for SQLiScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.fuzzing.sqli_scanner import SQLiScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(url: str = "http://localhost/login", field: str = "username") -> AttackVector:
    return AttackVector(
        target_url=url,
        method="POST",
        field_name=field,
        surface_type=SurfaceType.FORM_FIELD,
        extra_fields={},
        priority=1,
        vuln_types=[VulnType.SQLI],
    )


def _mock_response(text: str, elapsed_s: float = 0.1) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = text
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = elapsed_s
    return resp


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        target_url="http://localhost",
        output_dir="/tmp/dast",
        max_payloads_per_vector=10,
    )


@pytest.fixture()
def mock_http(settings: Settings) -> MagicMock:
    client = MagicMock()
    client.post = AsyncMock()
    client.get = AsyncMock()
    client.post_no_retry = AsyncMock()
    client.get_no_retry = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_error_based_detection(settings: Settings, mock_http: MagicMock) -> None:
    error_html = "<html>you have an error in your SQL syntax</html>"
    mock_http.post = AsyncMock(return_value=_mock_response(error_html))
    mock_http.post_no_retry = AsyncMock(return_value=_mock_response(error_html))

    scanner = SQLiScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "' OR 1=1--")

    assert finding is not None
    assert finding.vuln_type == VulnType.SQLI
    assert finding.confidence in (Confidence.CONFIRMED, Confidence.LIKELY)


@pytest.mark.asyncio
async def test_no_finding_on_clean_response(settings: Settings, mock_http: MagicMock) -> None:
    clean_html = "<html><body>Welcome back!</body></html>"
    mock_http.post = AsyncMock(return_value=_mock_response(clean_html))
    mock_http.post_no_retry = AsyncMock(return_value=_mock_response(clean_html))

    scanner = SQLiScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "normal_value")

    assert finding is None


@pytest.mark.asyncio
async def test_union_marker_detection(settings: Settings, mock_http: MagicMock) -> None:
    union_html = "<html><body>DASTUNION7654321 data</body></html>"
    mock_http.post = AsyncMock(return_value=_mock_response(union_html))
    mock_http.post_no_retry = AsyncMock(return_value=_mock_response(union_html))

    scanner = SQLiScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "' UNION SELECT 'DASTUNION7654321'--")

    assert finding is not None
    assert finding.vuln_type == VulnType.SQLI
