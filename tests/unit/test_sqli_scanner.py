"""Unit tests for SQLiScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import Confidence
from src.core.config import Settings
from src.fuzzing.sqli_scanner import SQLiScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(url: str = "http://localhost/login", field: str = "username") -> AttackVector:
    return AttackVector(
        source_url=url,
        target_url=url,
        method="POST",
        field_name=field,
        surface=SurfaceType.FORM_FIELD,
        field_context=f"<form><input name='{field}'>",
        extra_params={},
        priority=1,
        applicable_vulns=[VulnType.SQLI],
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


@pytest.mark.asyncio
async def test_union_suppressed_on_reflective_endpoint(
    settings: Settings, mock_http: MagicMock
) -> None:
    """A page that echoes its input must NOT produce UNION-based findings.

    Regression for the 42-FP UNION storm in sqli_monotematico_profundo:
    xss_r/xss_s/csp/fi simply ``echo $_GET['name']`` so the union marker
    appeared in the response without any database touching the request.
    """

    def _echo(*args: object, **kwargs: object) -> MagicMock:
        # Whatever value is sent, echo it straight back.  This mirrors how
        # DVWA's xss_r/xss_s pages behave — exactly the FP source.
        data = kwargs.get("data") or {}
        sent = next(iter(data.values())) if isinstance(data, dict) and data else ""
        return _mock_response(f"<html><body>Hello {sent}</body></html>")

    mock_http.post = AsyncMock(side_effect=_echo)
    mock_http.post_no_retry = AsyncMock(side_effect=_echo)

    scanner = SQLiScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "' UNION SELECT 'DASTUNION7654321'--")

    assert finding is None


@pytest.mark.asyncio
async def test_reflective_check_cached_per_vector(settings: Settings, mock_http: MagicMock) -> None:
    """The canary probe runs at most once per (url, field)."""

    call_log: list[str] = []

    def _track(*args: object, **kwargs: object) -> MagicMock:
        data = kwargs.get("data") or {}
        sent = next(iter(data.values())) if isinstance(data, dict) and data else ""
        call_log.append(str(sent))
        return _mock_response(f"<html>{sent}</html>")

    mock_http.post = AsyncMock(side_effect=_track)

    scanner = SQLiScanner(settings, mock_http)
    vector = _make_vector()
    # Two consecutive UNION attempts on the same vector — only one canary
    # request must be issued.
    await scanner._detect(vector, "' UNION SELECT 'DASTUNION7654321'--")
    await scanner._detect(vector, "1' UNION SELECT NULL,'DASTUNION7654321'--")

    canary_calls = [c for c in call_log if c.startswith("DASTCANARY")]
    assert len(canary_calls) == 1, f"Expected 1 canary request, got {len(canary_calls)}"
