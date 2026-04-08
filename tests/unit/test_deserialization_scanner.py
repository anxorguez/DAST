"""Unit tests for DeserializationScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import Confidence
from src.core.config import Settings
from src.fuzzing.deserialization_scanner import DeserializationScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(
    url: str = "http://localhost/api", field: str = "data"
) -> AttackVector:
    return AttackVector(
        source_url=url,
        target_url=url,
        method="POST",
        surface=SurfaceType.JSON_BODY,
        field_name=field,
        field_context="POST body field",
        applicable_vulns=[VulnType.DESERIALIZATION],
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
async def test_confirmed_java_deser_exception(
    settings: Settings, mock_http: MagicMock
) -> None:
    """CONFIRMED when Java deserialization exception appears in response."""
    error_body = (
        "java.io.InvalidClassException: com.example.Gadget; "
        "local class incompatible: stream classdesc serialVersionUID = 1"
    )
    mock_http.post = AsyncMock(return_value=_mock_response(error_body, 500))

    scanner = DeserializationScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "rO0ABXNyAANmb28=")

    assert finding is not None
    assert finding.vuln_type == VulnType.DESERIALIZATION
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_confirmed_php_unserialize_error(
    settings: Settings, mock_http: MagicMock
) -> None:
    """CONFIRMED when PHP unserialize() error appears."""
    php_error = "unserialize(): Error at offset 0 of 10 bytes"
    mock_http.post = AsyncMock(return_value=_mock_response(php_error, 500))

    scanner = DeserializationScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, 'O:12:"GhostClass99":0:{}')

    assert finding is not None
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_likely_on_500_with_java_payload(
    settings: Settings, mock_http: MagicMock
) -> None:
    """LIKELY when HTTP 500 returned for a Java-serialized-looking payload."""
    mock_http.post = AsyncMock(
        return_value=_mock_response("Internal Server Error", 500)
    )

    scanner = DeserializationScanner(settings, mock_http)
    vector = _make_vector()
    # Java serialization base64 prefix
    finding = await scanner._detect(vector, "rO0ABXNy")

    assert finding is not None
    assert finding.confidence == Confidence.LIKELY


@pytest.mark.asyncio
async def test_no_finding_on_clean_200(
    settings: Settings, mock_http: MagicMock
) -> None:
    """No finding when response is a normal 200 with no error indicators."""
    mock_http.post = AsyncMock(
        return_value=_mock_response('{"status":"ok"}', 200)
    )

    scanner = DeserializationScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "normal_value")

    assert finding is None
