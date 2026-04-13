"""Unit tests for SSRFScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import Confidence
from src.core.config import Settings
from src.fuzzing.ssrf_scanner import SSRFScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(
    url: str = "http://localhost/fetch",
    field: str = "url",
) -> AttackVector:
    return AttackVector(
        source_url=url,
        target_url=url,
        method="GET",
        surface=SurfaceType.URL_PARAM,
        field_name=field,
        field_context=f"URL query parameter: {field}",
        applicable_vulns=[VulnType.SSRF],
    )


def _mock_response(text: str, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = {}
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
    client.post = AsyncMock()
    client.get_no_retry = AsyncMock()
    client.post_no_retry = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_confirmed_on_aws_metadata_content(settings: Settings, mock_http: MagicMock) -> None:
    """CONFIRMED when response contains AWS metadata key."""
    aws_html = "<html><body>ami-id: ami-0abc1234</body></html>"
    mock_http.get = AsyncMock(return_value=_mock_response(aws_html))
    mock_http.get_no_retry = AsyncMock(return_value=_mock_response(aws_html))

    scanner = SSRFScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "http://169.254.169.254/latest/meta-data/")

    assert finding is not None
    assert finding.vuln_type == VulnType.SSRF
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_confirmed_on_passwd_content(settings: Settings, mock_http: MagicMock) -> None:
    """/etc/passwd content in response yields CONFIRMED."""
    passwd_body = "root:x:0:0:root:/root:/bin/bash"
    mock_http.get = AsyncMock(return_value=_mock_response(passwd_body))
    mock_http.get_no_retry = AsyncMock(return_value=_mock_response(passwd_body))

    scanner = SSRFScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "file:///etc/passwd")

    assert finding is not None
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_likely_on_significant_size_diff(settings: Settings, mock_http: MagicMock) -> None:
    """LIKELY when response size differs significantly from baseline."""
    baseline = _mock_response("Welcome", 200)
    large_response = _mock_response("A" * 500, 200)

    call_count = 0

    async def side_effect(*args: object, **kwargs: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return baseline
        return large_response

    mock_http.get = AsyncMock(side_effect=side_effect)
    mock_http.get_no_retry = AsyncMock(side_effect=side_effect)

    scanner = SSRFScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "http://127.0.0.1/")

    assert finding is not None
    assert finding.confidence == Confidence.LIKELY


@pytest.mark.asyncio
async def test_no_finding_on_clean_response(settings: Settings, mock_http: MagicMock) -> None:
    """No finding on a response that contains no SSRF indicators."""
    clean = _mock_response("<html>normal page</html>", 200)
    mock_http.get = AsyncMock(return_value=clean)
    mock_http.get_no_retry = AsyncMock(return_value=clean)

    scanner = SSRFScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "http://safe.example.com/")

    assert finding is None
