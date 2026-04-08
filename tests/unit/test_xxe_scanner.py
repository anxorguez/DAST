"""Unit tests for XXEScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import Confidence
from src.core.config import Settings
from src.fuzzing.xxe_scanner import XXEScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(url: str = "http://localhost/xml", field: str = "data") -> AttackVector:
    return AttackVector(
        source_url=url,
        target_url=url,
        method="POST",
        surface=SurfaceType.XML_BODY,
        field_name=field,
        field_context="XML body field",
        applicable_vulns=[VulnType.XXE],
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
    client.post = AsyncMock()
    client.post_no_retry = AsyncMock()
    client.get = AsyncMock()
    client.get_no_retry = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_confirmed_on_passwd_reflection(
    settings: Settings, mock_http: MagicMock
) -> None:
    """CONFIRMED when /etc/passwd content appears in response."""
    passwd_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
    mock_http.post_no_retry = AsyncMock(return_value=_mock_response(passwd_body))
    mock_http.post = AsyncMock(return_value=_mock_response(passwd_body))

    scanner = XXEScanner(settings, mock_http)
    vector = _make_vector()
    payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    finding = await scanner._detect(vector, payload)

    assert finding is not None
    assert finding.vuln_type == VulnType.XXE
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_likely_on_xml_parser_error(
    settings: Settings, mock_http: MagicMock
) -> None:
    """LIKELY when the response contains an XML parser error."""
    error_body = "<error>SAXParseException: external entity reference not allowed</error>"
    mock_http.post_no_retry = AsyncMock(return_value=_mock_response(error_body, 500))
    mock_http.post = AsyncMock(return_value=_mock_response(error_body, 500))

    scanner = XXEScanner(settings, mock_http)
    vector = _make_vector()
    payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    finding = await scanner._detect(vector, payload)

    assert finding is not None
    assert finding.confidence == Confidence.LIKELY


@pytest.mark.asyncio
async def test_no_finding_on_clean_response(
    settings: Settings, mock_http: MagicMock
) -> None:
    """No finding when response contains no XXE indicators."""
    clean = _mock_response("<result>ok</result>", 200)
    mock_http.post_no_retry = AsyncMock(return_value=clean)
    mock_http.post = AsyncMock(return_value=clean)

    scanner = XXEScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "<foo>test</foo>")

    assert finding is None
