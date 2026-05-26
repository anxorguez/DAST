"""Unit tests for the HTTPClient cf_clearance bridge.

Cover two behaviours added with the cf_clearance bridge:

* the crawler's ``User-Agent`` is propagated onto every outgoing request
  (a cf_clearance cookie is bound to the UA that requested it);
* a response carrying ``X-Cf-Sim-Challenge: expired``/``missing`` triggers
  the refresh callback exactly once and the request is retried, while a
  permanent challenge (``ua_mismatch``) or a missing callback does not.

All assertions that touch ``client._client`` stay inside the ``async with``
block: ``__aexit__`` resets it to ``None``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from src.core.http_client import _DEFAULT_USER_AGENT, HTTPClient


def _challenge(reason: str) -> httpx.Response:
    """Build a 403 response carrying an ``X-Cf-Sim-Challenge`` marker."""
    return httpx.Response(403, headers={"X-Cf-Sim-Challenge": reason})


# ---------------------------------------------------------------------------
# User-Agent propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_agent_propagated_to_request_headers() -> None:
    """A provided user_agent must override httpx's default UA."""
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    async with HTTPClient(timeout=5, user_agent=ua) as client:
        assert client._client is not None
        assert client._client.headers.get("User-Agent") == ua


@pytest.mark.asyncio
async def test_default_user_agent_when_none_supplied() -> None:
    """With no user_agent the framework default UA is used."""
    async with HTTPClient(timeout=5) as client:
        assert client._client is not None
        assert client._client.headers.get("User-Agent") == _DEFAULT_USER_AGENT


# ---------------------------------------------------------------------------
# Reactive refresh on a recoverable challenge
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_callback_invoked_once_on_expired() -> None:
    """An ``expired`` challenge refreshes the session and retries once."""
    calls: list[str] = []

    async def refresh_cb() -> dict[str, Any]:
        calls.append("refresh")
        return {
            "cookies": [{"name": "cf_clearance", "value": "fresh"}],
            "user_agent": "RefreshedUA",
        }

    async with HTTPClient(timeout=5, cf_clearance_refresh_callback=refresh_cb) as client:
        assert client._client is not None
        client._client.get = AsyncMock(  # type: ignore[method-assign]
            side_effect=[_challenge("expired"), httpx.Response(200)]
        )
        response = await client.get("http://dvwa-cf/")

        assert response.status_code == 200
        assert calls == ["refresh"]
        assert client._client.get.call_count == 2


@pytest.mark.asyncio
async def test_refresh_applies_new_cookies_and_ua() -> None:
    """After a refresh the renewed cookie + UA are pushed onto the client."""

    async def refresh_cb() -> dict[str, Any]:
        return {
            "cookies": [{"name": "cf_clearance", "value": "fresh"}],
            "user_agent": "RefreshedUA",
        }

    async with HTTPClient(timeout=5, cf_clearance_refresh_callback=refresh_cb) as client:
        assert client._client is not None
        client._client.get = AsyncMock(  # type: ignore[method-assign]
            side_effect=[_challenge("missing"), httpx.Response(200)]
        )
        await client.get("http://dvwa-cf/")

        assert "cf_clearance=fresh" in client._client.headers.get("Cookie", "")
        assert client._client.headers.get("User-Agent") == "RefreshedUA"


@pytest.mark.asyncio
async def test_retry_failure_does_not_loop() -> None:
    """If the retry still fails, the second response is returned — no loop."""
    calls: list[str] = []

    async def refresh_cb() -> dict[str, Any]:
        calls.append("refresh")
        return {"cookies": [], "user_agent": "UA"}

    async with HTTPClient(timeout=5, cf_clearance_refresh_callback=refresh_cb) as client:
        assert client._client is not None
        client._client.get = AsyncMock(  # type: ignore[method-assign]
            side_effect=[_challenge("expired"), _challenge("expired")]
        )
        response = await client.get("http://dvwa-cf/")

        assert response.status_code == 403
        assert calls == ["refresh"]  # refreshed exactly once
        assert client._client.get.call_count == 2


@pytest.mark.asyncio
async def test_permanent_challenge_is_not_refreshed() -> None:
    """``ua_mismatch`` is a dead session: refreshing would not help, so skip it."""
    calls: list[str] = []

    async def refresh_cb() -> dict[str, Any]:
        calls.append("refresh")
        return {"cookies": [], "user_agent": "UA"}

    async with HTTPClient(timeout=5, cf_clearance_refresh_callback=refresh_cb) as client:
        assert client._client is not None
        client._client.get = AsyncMock(  # type: ignore[method-assign]
            return_value=_challenge("ua_mismatch")
        )
        response = await client.get("http://dvwa-cf/")

        assert response.status_code == 403
        assert calls == []
        assert client._client.get.call_count == 1


@pytest.mark.asyncio
async def test_no_callback_returns_challenge_verbatim() -> None:
    """Without a callback a challenge response is returned untouched."""
    async with HTTPClient(timeout=5) as client:
        assert client._client is not None
        client._client.get = AsyncMock(  # type: ignore[method-assign]
            return_value=_challenge("expired")
        )
        response = await client.get("http://dvwa-cf/")

        assert response.status_code == 403
        assert client._client.get.call_count == 1


@pytest.mark.asyncio
async def test_post_also_refreshes_on_challenge() -> None:
    """The refresh path covers POST requests too, not just GET."""

    async def refresh_cb() -> dict[str, Any]:
        return {"cookies": [{"name": "cf_clearance", "value": "x"}], "user_agent": "UA"}

    async with HTTPClient(timeout=5, cf_clearance_refresh_callback=refresh_cb) as client:
        assert client._client is not None
        client._client.post = AsyncMock(  # type: ignore[method-assign]
            side_effect=[_challenge("expired"), httpx.Response(200)]
        )
        response = await client.post("http://dvwa-cf/", data={"a": "b"})

        assert response.status_code == 200
        assert client._client.post.call_count == 2
