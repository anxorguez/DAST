"""Integration tests for the cf_clearance bridge against the cf-sim fixture.

Prerequisites (satisfied by start.sh or the GitHub Actions test workflow):
  - cf-sim running at http://localhost:8089 (proxies to dvwa-origin)
  - dvwa-origin running behind it
  - Environment variable INTEGRATION_TESTS=1 is set

These tests are skipped automatically when cf-sim is not reachable.

``test_refresh_on_expired`` additionally needs cf-sim started with a short
``CLEARANCE_TTL_SECONDS`` (<= 10) so the clearance can expire within the
test; export the same value so the test knows how long to wait.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import httpx
import pytest

from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.crawler.crawler import Crawler

CF_SIM_URL = os.getenv("CF_SIM_URL", "http://localhost:8089")


def _cf_sim_reachable() -> bool:
    try:
        r = httpx.get(f"{CF_SIM_URL}/cdn-cgi/challenge-page", timeout=5)
        return r.status_code < 500
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _cf_sim_reachable() or not os.getenv("INTEGRATION_TESTS"),
    reason="cf-sim not reachable or INTEGRATION_TESTS env var not set",
)


def _settings(tmp_path: Path) -> Settings:
    """Settings pointing the crawler at the cf-sim fixture, no auth."""
    return Settings(
        target_url=CF_SIM_URL,
        output_dir=str(tmp_path),
        auth_enabled=False,
        log_level="INFO",
    )


@pytest.mark.asyncio
async def test_vanilla_httpx_gets_403() -> None:
    """A plain HTTP client cannot solve the JS challenge — it gets 403."""
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        response = await client.get(f"{CF_SIM_URL}/index.php")

    assert response.status_code == 403
    assert response.headers.get("X-Cf-Sim-Challenge") == "missing"


@pytest.mark.asyncio
async def test_bridged_httpx_passes(tmp_path: Path) -> None:
    """Cookies + UA captured by Playwright let a plain httpx request through."""
    crawler = Crawler(_settings(tmp_path))
    session = await crawler.refresh_session_async()

    assert any(c.get("name") == "cf_clearance" for c in session["cookies"]), (
        "Playwright did not obtain a cf_clearance cookie from cf-sim"
    )

    async with HTTPClient(
        timeout=20,
        session_cookies=session["cookies"],
        user_agent=session["user_agent"],
    ) as client:
        response = await client.get(f"{CF_SIM_URL}/index.php")

    assert response.status_code != 403
    assert response.headers.get("X-Cf-Sim-Challenge") is None


@pytest.mark.asyncio
async def test_ua_mismatch_invalidates(tmp_path: Path) -> None:
    """A valid cookie sent with the wrong User-Agent is rejected."""
    crawler = Crawler(_settings(tmp_path))
    session = await crawler.refresh_session_async()

    async with HTTPClient(
        timeout=20,
        session_cookies=session["cookies"],
        user_agent="totally-different-agent/1.0",
    ) as client:
        response = await client.get(f"{CF_SIM_URL}/index.php")

    assert response.status_code == 403
    assert response.headers.get("X-Cf-Sim-Challenge") == "ua_mismatch"


@pytest.mark.asyncio
async def test_refresh_on_expired(tmp_path: Path) -> None:
    """An expired clearance triggers a Playwright refresh and the retry passes."""
    ttl = int(os.getenv("CLEARANCE_TTL_SECONDS", "1800"))
    if ttl > 10:
        pytest.skip(
            "Start cf-sim with CLEARANCE_TTL_SECONDS<=10 and export the same "
            "value to exercise the expiry/refresh path."
        )

    crawler = Crawler(_settings(tmp_path))
    session = await crawler.refresh_session_async()

    # Wait until the clearance issued above has expired server-side.
    time.sleep(ttl + 2)

    async with HTTPClient(
        timeout=25,
        session_cookies=session["cookies"],
        user_agent=session["user_agent"],
        cf_clearance_refresh_callback=crawler.refresh_session_async,
    ) as client:
        response = await client.get(f"{CF_SIM_URL}/index.php")

    # The first request hits an expired cookie (X-Cf-Sim-Challenge: expired),
    # the bridge re-launches Playwright, and the retried request goes through.
    assert response.status_code != 403
    assert response.headers.get("X-Cf-Sim-Challenge") is None
