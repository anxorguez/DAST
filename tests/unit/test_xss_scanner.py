"""Unit tests for XSSScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.fuzzing.xss_scanner import XSSScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(url: str = "http://localhost/search", field: str = "q") -> AttackVector:
    return AttackVector(
        target_url=url,
        method="GET",
        field_name=field,
        surface_type=SurfaceType.URL_PARAM,
        extra_fields={},
        priority=1,
        vuln_types=[VulnType.XSS],
    )


def _mock_response(text: str) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = text
    resp.elapsed = MagicMock()
    resp.elapsed.total_seconds.return_value = 0.05
    return resp


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        target_url="http://localhost",
        output_dir="/tmp/dast",
        max_payloads_per_vector=10,
    )


@pytest.fixture()
def mock_http() -> MagicMock:
    client = MagicMock()
    client.get = AsyncMock()
    client.post = AsyncMock()
    client.get_no_retry = AsyncMock()
    client.post_no_retry = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_reflected_payload_detected(settings: Settings, mock_http: MagicMock) -> None:
    payload = "<script>alert(1)</script>"
    html = f"<html><body>Search results for: {payload}</body></html>"
    mock_http.get = AsyncMock(return_value=_mock_response(html))
    mock_http.get_no_retry = AsyncMock(return_value=_mock_response(html))

    scanner = XSSScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), payload)

    assert finding is not None
    assert finding.vuln_type == VulnType.XSS


@pytest.mark.asyncio
async def test_no_finding_when_payload_not_reflected(settings: Settings, mock_http: MagicMock) -> None:
    payload = "<script>alert(1)</script>"
    html = "<html><body>Search results for: &lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
    mock_http.get = AsyncMock(return_value=_mock_response(html))
    mock_http.get_no_retry = AsyncMock(return_value=_mock_response(html))

    scanner = XSSScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), payload)

    # Escaped output means the payload was not injected unescaped
    assert finding is None


@pytest.mark.asyncio
async def test_event_handler_partial_match(settings: Settings, mock_http: MagicMock) -> None:
    payload = "<img src=x onerror=alert(1)>"
    html = f"<html><body><img src=x onerror=alert(1)></body></html>"
    mock_http.get = AsyncMock(return_value=_mock_response(html))
    mock_http.get_no_retry = AsyncMock(return_value=_mock_response(html))

    scanner = XSSScanner(settings, mock_http)
    finding = await scanner._detect(_make_vector(), payload)

    assert finding is not None
    assert finding.vuln_type == VulnType.XSS
