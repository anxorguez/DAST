"""Unit tests for PathTraversalScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import Confidence
from src.core.config import Settings
from src.fuzzing.path_traversal_scanner import PathTraversalScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_vector(
    url: str = "http://localhost/download",
    field: str = "file",
) -> AttackVector:
    return AttackVector(
        source_url=url,
        target_url=url,
        method="GET",
        surface=SurfaceType.URL_PARAM,
        field_name=field,
        field_context=f"URL query parameter: {field}",
        applicable_vulns=[VulnType.PATH_TRAVERSAL],
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
    client.get_no_retry = AsyncMock()
    client.post = AsyncMock()
    client.post_no_retry = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_confirmed_on_passwd_content(
    settings: Settings, mock_http: MagicMock
) -> None:
    """/etc/passwd content in response yields CONFIRMED."""
    passwd_body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
    mock_http.get = AsyncMock(return_value=_mock_response(passwd_body))

    scanner = PathTraversalScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "../../../etc/passwd")

    assert finding is not None
    assert finding.vuln_type == VulnType.PATH_TRAVERSAL
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_confirmed_on_windows_ini(
    settings: Settings, mock_http: MagicMock
) -> None:
    """win.ini content in response yields CONFIRMED."""
    ini_body = "[fonts]\r\n[extensions]\r\nWINDOWS=Win32"
    mock_http.get = AsyncMock(return_value=_mock_response(ini_body))

    scanner = PathTraversalScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, r"..\windows\win.ini")

    assert finding is not None
    assert finding.confidence == Confidence.CONFIRMED


@pytest.mark.asyncio
async def test_likely_on_file_not_found_error(
    settings: Settings, mock_http: MagicMock
) -> None:
    """Filesystem error in response yields LIKELY."""
    error_body = "Warning: file_get_contents(): Failed to open stream: No such file or directory"
    mock_http.get = AsyncMock(return_value=_mock_response(error_body, 200))

    scanner = PathTraversalScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "../../etc/passwd")

    assert finding is not None
    assert finding.confidence == Confidence.LIKELY


@pytest.mark.asyncio
async def test_no_finding_on_clean_response(
    settings: Settings, mock_http: MagicMock
) -> None:
    """No finding when response is clean."""
    mock_http.get = AsyncMock(return_value=_mock_response("<html>file contents</html>"))

    scanner = PathTraversalScanner(settings, mock_http)
    vector = _make_vector()
    finding = await scanner._detect(vector, "report.pdf")

    assert finding is None
