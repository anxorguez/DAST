"""Unit tests for HTTPClient session-cookie propagation and retry semantics."""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from src.core.http_client import HTTPClient, _build_cookie_header


@pytest.mark.asyncio
async def test_session_cookies_installed_on_client() -> None:
    """Cookies from Playwright must end up in the ``Cookie`` request header.

    Without this, fuzzing requests are unauthenticated and every vulnerable
    endpoint redirects back to login.
    """
    cookies = [
        {"name": "PHPSESSID", "value": "abc123", "domain": "dvwa", "path": "/"},
        {"name": "security", "value": "low", "domain": "dvwa", "path": "/"},
    ]
    async with HTTPClient(timeout=5, session_cookies=cookies) as client:
        assert client._client is not None
        header = client._client.headers.get("Cookie", "")
        assert "PHPSESSID=abc123" in header
        assert "security=low" in header


@pytest.mark.asyncio
async def test_empty_session_cookies_leave_client_working() -> None:
    """An empty cookie list must not set a Cookie header at all."""
    async with HTTPClient(timeout=5) as client:
        assert client._client is not None
        assert client._client.headers.get("Cookie") is None


def test_single_label_host_cookie_is_serialised() -> None:
    """Cookies from single-label Docker hosts (e.g. 'dvwa') must reach the header.

    The previous jar-based implementation silently dropped these because
    Python's default cookie policy treats single-label domains as invalid
    (RFC 6265 §5.1.3). The raw-header approach sidesteps the jar entirely.
    """
    cookies = [{"name": "PHPSESSID", "value": "abc123", "domain": "dvwa", "path": "/"}]
    header = _build_cookie_header(cookies)
    assert header == "PHPSESSID=abc123"


def test_cookies_without_name_are_skipped() -> None:
    cookies = [
        {"name": "", "value": "junk"},
        {"name": "real", "value": "x"},
    ]
    assert _build_cookie_header(cookies) == "real=x"


@pytest.mark.asyncio
async def test_default_get_does_not_retry() -> None:
    """Default ``max_retries=1`` must mean a single attempt.

    Regression: when the fuzzer used a tenacity-decorated GET, every
    payload-induced timeout produced 3 attempts × request_timeout of latency,
    which caused the pipeline to hang for tens of minutes against a slow
    target.  The default must be a single attempt for the fuzz path.
    """
    async with HTTPClient(timeout=1) as client:
        assert client._client is not None
        client._client.get = AsyncMock(  # type: ignore[method-assign]
            side_effect=httpx.ReadTimeout("dead")
        )
        with pytest.raises(httpx.ReadTimeout):
            await client.get("http://localhost/")
        assert client._client.get.call_count == 1


@pytest.mark.asyncio
async def test_get_retries_when_max_retries_above_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-in ``max_retries=3`` must retry transient errors that many times."""

    async def _instant_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("src.core.http_client.asyncio.sleep", _instant_sleep)

    async with HTTPClient(timeout=1, max_retries=3) as client:
        assert client._client is not None
        client._client.get = AsyncMock(  # type: ignore[method-assign]
            side_effect=httpx.ReadTimeout("dead")
        )
        with pytest.raises(httpx.ReadTimeout):
            await client.get("http://localhost/")
        assert client._client.get.call_count == 3
