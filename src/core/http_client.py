"""Shared async HTTP client with optional retry logic.

Retries are **off by default** because this client is used by the fuzzing
scanners, where toxic payloads are *expected* to provoke timeouts and 5xx
responses.  Retrying those requests multiplies the per-payload cost (e.g.
3 attempts × 30 s timeout ≈ 90 s of wall time) and used to keep the pipeline
hung for tens of minutes against a slow or partially dead target.

Callers that genuinely need retries (e.g. flaky-network scenarios outside the
fuzz path) can opt in by constructing the client with ``max_retries > 1``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from loguru import logger

from src.core.blocked_tracker import BlockedResponseTracker

# Default User-Agent sent when the caller does not propagate one from the
# crawler's BrowserContext.
_DEFAULT_USER_AGENT = "DAST-Framework/0.1 (security-testing)"

# cf_clearance challenge markers (set by the cf-sim fixture via the
# ``X-Cf-Sim-Challenge`` response header) that the bridge treats as
# *recoverable* — refreshing the cookie via Playwright may fix them.
# ``ua_mismatch`` / ``invalid_token`` are deliberately excluded: they signal
# a dead session that a refresh would not repair.
_REFRESHABLE_CHALLENGES: frozenset[str] = frozenset({"expired", "missing"})

# Network exceptions that are reasonable to retry: transient connection or
# DNS issues, read/write timeouts, and remote protocol violations.  HTTP-level
# errors (4xx/5xx) are *not* retried because the response body is often the
# detection signal scanners depend on.
_RETRYABLE_EXC: tuple[type[BaseException], ...] = (
    httpx.TimeoutException,
    httpx.NetworkError,
    httpx.RemoteProtocolError,
)


def _build_cookie_header(session_cookies: list[dict[str, Any]]) -> str:
    """Serialise Playwright-format cookies to a raw ``Cookie`` header value."""
    parts: list[str] = []
    for entry in session_cookies:
        name = str(entry.get("name", ""))
        value = str(entry.get("value", ""))
        if not name:
            continue
        parts.append(f"{name}={value}")
    return "; ".join(parts)


class HTTPClient:
    """Async HTTP client wrapper around httpx.AsyncClient.

    Provides GET and POST helpers with optional retries on transient errors.
    Use as an async context manager.

    Example::

        async with HTTPClient(timeout=30) as client:  # no retries (default)
            response = await client.get("http://example.com/page?id=1")

        async with HTTPClient(timeout=30, max_retries=3) as client:
            response = await client.get("http://example.com/page?id=1")

    Retry semantics
    ---------------
    * ``max_retries=1`` (the default) → single attempt, no retry.  This is the
      correct setting for fuzzing: a payload that times out is informative;
      retrying it 3× burns ~90 s and rarely succeeds.
    * ``max_retries>1`` → exponential back-off (1 s … 8 s) between attempts.
      Only ``httpx`` network/timeout errors trigger a retry; HTTP responses
      (including 5xx) are returned to the caller verbatim.

    Session cookies
    ---------------
    When *session_cookies* is provided (Playwright-format list of dicts with
    keys ``name`` and ``value``), they are serialised into a static ``Cookie``
    request header so every outgoing request inherits the authenticated
    browser session.

    Why a raw header instead of ``httpx.Cookies``: Python's default cookie
    jar silently refuses to send cookies whose domain attribute has no dot
    (RFC 6265 §5.1.3), and Docker Compose scan targets are always
    single-label hostnames. Forcing a permissive jar policy is not
    sufficient — ``httpx`` rebuilds its own jar copy internally and reapplies
    the default policy, so cookies get silently dropped on every request.
    Setting the ``Cookie`` header directly sidesteps all of that.

    User-Agent propagation
    ----------------------
    When *user_agent* is provided it is fixed as the ``User-Agent`` header on
    every outgoing request, overriding httpx's default (``python-httpx/x``).
    This is what the cf_clearance bridge uses: the cookie minted by the
    cf-sim fixture is bound to the UA that requested it, so the fuzzer must
    reuse the crawler's browser UA or the cookie is rejected as
    ``ua_mismatch``.

    cf_clearance reactive refresh
    -----------------------------
    When *cf_clearance_refresh_callback* is provided and a response carries
    ``X-Cf-Sim-Challenge: expired`` (or ``missing``), the callback is invoked
    to renew the session (cookies + UA) via Playwright and the request is
    retried **exactly once**.  If the retry still fails the second response
    is returned verbatim — no loop.
    """

    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 1,
        session_cookies: list[dict[str, Any]] | None = None,
        user_agent: str | None = None,
        cf_clearance_refresh_callback: Callable[[], Awaitable[dict[str, Any]]] | None = None,
        blocked_tracker: BlockedResponseTracker | None = None,
    ) -> None:
        self._timeout = timeout
        # ``max_retries`` is the *total* number of attempts.  1 means no retry.
        self._max_retries = max(1, max_retries)
        self._session_cookies = session_cookies or []
        self._user_agent = user_agent
        self._cf_clearance_refresh_callback = cf_clearance_refresh_callback
        self._blocked_tracker = blocked_tracker
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HTTPClient:
        headers: dict[str, str] = {"User-Agent": self._user_agent or _DEFAULT_USER_AGENT}
        cookie_header = _build_cookie_header(self._session_cookies)
        if cookie_header:
            headers["Cookie"] = cookie_header

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=True,
            verify=False,  # Target may use self-signed certificates
            headers=headers,
        )
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform a GET request, retrying ``max_retries-1`` times on transient errors."""
        assert self._client is not None, "HTTPClient used outside context manager"
        client = self._client
        return await self._send_with_refresh(
            lambda: self._with_retries(lambda: client.get(url, params=params, headers=headers))
        )

    async def post(
        self,
        url: str,
        *,
        data: dict[str, str] | None = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform a POST request, retrying ``max_retries-1`` times on transient errors."""
        assert self._client is not None, "HTTPClient used outside context manager"
        client = self._client
        return await self._send_with_refresh(
            lambda: self._with_retries(
                lambda: client.post(url, data=data, content=content, headers=headers)
            )
        )

    async def get_no_retry(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response:
        """GET without retry (used for time-based measurements)."""
        assert self._client is not None, "HTTPClient used outside context manager"
        client = self._client
        return await self._send_with_refresh(
            lambda: client.get(
                url, params=params, headers=headers, follow_redirects=follow_redirects
            )
        )

    async def post_no_retry(
        self,
        url: str,
        *,
        data: dict[str, str] | None = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response:
        """POST without retry (used for time-based measurements)."""
        assert self._client is not None, "HTTPClient used outside context manager"
        client = self._client
        return await self._send_with_refresh(
            lambda: client.post(
                url,
                data=data,
                content=content,
                headers=headers,
                follow_redirects=follow_redirects,
            )
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _send_with_refresh(self, send: Any) -> httpx.Response:
        """Run *send*; on a recoverable cf_clearance challenge, refresh and retry once.

        *send* is a zero-argument coroutine factory that performs the actual
        request.  When the response carries ``X-Cf-Sim-Challenge: expired``
        or ``missing`` and a refresh callback is configured, the session
        (cookies + User-Agent) is renewed via Playwright and *send* is run a
        second time.  The second response is returned verbatim — there is no
        further refresh, so a still-failing target cannot cause a loop.
        """
        response: httpx.Response = await send()
        if self._blocked_tracker is not None:
            await self._blocked_tracker.record(response)

        if self._cf_clearance_refresh_callback is None:
            return response

        marker = response.headers.get("X-Cf-Sim-Challenge", "")
        if marker not in _REFRESHABLE_CHALLENGES:
            return response

        logger.info(
            "cf_clearance {m} — refreshing session via Playwright before retry",
            m=marker,
        )
        await self._refresh_session()
        # Retry exactly once; whatever comes back is returned to the caller.
        retry_response: httpx.Response = await send()
        if self._blocked_tracker is not None:
            await self._blocked_tracker.record(retry_response)
        return retry_response

    async def _refresh_session(self) -> None:
        """Invoke the refresh callback and apply the renewed cookies + UA.

        The callback re-launches Playwright (see
        :meth:`Crawler.refresh_session_async`) and returns a dict with
        ``cookies`` and ``user_agent``.  Both are pushed onto the live
        ``httpx`` client headers so the retried request inherits them.
        """
        if self._cf_clearance_refresh_callback is None:
            return

        new_session = await self._cf_clearance_refresh_callback()
        self._session_cookies = new_session.get("cookies") or []
        new_ua = new_session.get("user_agent")
        if new_ua:
            self._user_agent = str(new_ua)

        if self._client is not None:
            cookie_header = _build_cookie_header(self._session_cookies)
            if cookie_header:
                self._client.headers["Cookie"] = cookie_header
            if self._user_agent:
                self._client.headers["User-Agent"] = self._user_agent
        logger.info(
            "cf_clearance session refreshed (cookies={n})",
            n=len(self._session_cookies),
        )

    async def _with_retries(
        self,
        send: Any,
    ) -> httpx.Response:
        """Run *send* with at most ``self._max_retries`` total attempts.

        Single-attempt mode (the default) is the hot path for fuzzing and
        avoids any retry overhead.  Multi-attempt mode applies exponential
        back-off (1, 2, 4, ... up to 8 s) between attempts.
        """
        if self._max_retries <= 1:
            return await send()  # type: ignore[no-any-return]

        last_exc: BaseException | None = None
        for attempt in range(self._max_retries):
            try:
                return await send()  # type: ignore[no-any-return]
            except _RETRYABLE_EXC as exc:
                last_exc = exc
                remaining = self._max_retries - attempt - 1
                if remaining <= 0:
                    raise
                wait_s = min(8.0, float(1 << attempt))
                logger.debug(
                    "HTTPClient retrying after {e} (attempt {n}/{t}, sleeping {w}s)",
                    e=type(exc).__name__,
                    n=attempt + 1,
                    t=self._max_retries,
                    w=wait_s,
                )
                await asyncio.sleep(wait_s)
        # Unreachable: the loop always returns or raises.
        assert last_exc is not None
        raise last_exc
