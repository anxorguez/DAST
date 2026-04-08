"""Unit tests for OpenRedirectScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import Confidence
from src.core.config import Settings
from src.fuzzing.open_redirect_scanner import OpenRedirectScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(
    url: str = "http://localhost/login",
    field: str = "redirect",
) -> AttackVector:
    return AttackVector(
        source_url=url,
        target_url=url,
        method="GET",
        surface=SurfaceType.URL_PARAM,
        field_name=field,
        field_context=f"URL query parameter: {field}",
        applicable_vulns=[VulnType.OPEN_REDIRECT],
    )


def _mock_response(
    text: str,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = headers or {}
    return resp


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        target_url="http://localhost",
        output_dir="/tmp/dast",
        max_payloads_per_vector=10,
        concurrent_payloads=1,
    )


@pytest.fixture()
def mock_http() -> MagicMock:
    client = MagicMock()
    client.get = AsyncMock()
    client.get_no_retry = AsyncMock()
    client.post = AsyncMock()
    client.post_no_retry = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_confirmed_on_location_header(
    settings: Settings, mock_http: MagicMock
) -> None:
    """CONFIRMED when Location header points to probe domain."""
    redirect_resp = _mock_response(
        "",
        status=302,
        headers={"location": "https://evil.com/phishing"},
    )
    mock_http.get_no_retry = AsyncMock(return_value=redirect_resp)

    scanner = OpenRedirectScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "https://evil.com/phishing")

    assert finding is not None
    assert finding.vuln_type == VulnType.OPEN_REDIRECT
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_likely_on_meta_refresh(
    settings: Settings, mock_http: MagicMock
) -> None:
    """LIKELY when meta-refresh redirects to probe domain."""
    meta_body = (
        '<html><head>'
        '<meta http-equiv="refresh" content="0; url=https://evil.com/">'
        '</head></html>'
    )
    mock_http.get_no_retry = AsyncMock(
        return_value=_mock_response(meta_body, 200)
    )

    scanner = OpenRedirectScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "https://evil.com/")

    assert finding is not None
    assert finding.confidence == Confidence.LIKELY


@pytest.mark.asyncio
async def test_likely_on_js_redirect(
    settings: Settings, mock_http: MagicMock
) -> None:
    """LIKELY when JavaScript window.location points to probe domain."""
    js_body = "<script>window.location = 'https://evil.com/';</script>"
    mock_http.get_no_retry = AsyncMock(
        return_value=_mock_response(js_body, 200)
    )

    scanner = OpenRedirectScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "https://evil.com/")

    assert finding is not None
    assert finding.confidence == Confidence.LIKELY


@pytest.mark.asyncio
async def test_no_finding_on_internal_redirect(
    settings: Settings, mock_http: MagicMock
) -> None:
    """No finding when redirect goes to the same domain."""
    redirect_resp = _mock_response(
        "",
        status=302,
        headers={"location": "http://localhost/dashboard"},
    )
    mock_http.get_no_retry = AsyncMock(return_value=redirect_resp)

    scanner = OpenRedirectScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "/dashboard")

    assert finding is None


@pytest.mark.asyncio
async def test_no_finding_on_clean_200(
    settings: Settings, mock_http: MagicMock
) -> None:
    """No finding on a normal 200 response with no redirect indicators."""
    mock_http.get_no_retry = AsyncMock(
        return_value=_mock_response("<html>login page</html>", 200)
    )

    scanner = OpenRedirectScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "/home")

    assert finding is None
