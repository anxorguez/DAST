"""Shared async HTTP client with retry logic via tenacity."""

from __future__ import annotations

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential


class HTTPClient:
    """Async HTTP client wrapper around httpx.AsyncClient.

    Provides GET and POST helpers with automatic retries on transient errors
    (connection timeouts, 5xx responses). Use as an async context manager.

    Example::

        async with HTTPClient(timeout=30) as client:
            response = await client.get("http://example.com/page?id=1")
    """

    def __init__(self, timeout: int = 30, max_retries: int = 3) -> None:
        self._timeout = timeout
        self._max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> HTTPClient:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            follow_redirects=True,
            verify=False,  # Target may use self-signed certificates
            headers={"User-Agent": "DAST-Framework/0.1 (security-testing)"},
        )
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        reraise=True,
    )
    async def get(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform a GET request with automatic retries."""
        assert self._client is not None, "HTTPClient used outside context manager"
        return await self._client.get(url, params=params, headers=headers)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        reraise=True,
    )
    async def post(
        self,
        url: str,
        *,
        data: dict[str, str] | None = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Perform a POST request with automatic retries."""
        assert self._client is not None, "HTTPClient used outside context manager"
        return await self._client.post(url, data=data, content=content, headers=headers)

    async def get_no_retry(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """GET without retry (used for time-based measurements)."""
        assert self._client is not None, "HTTPClient used outside context manager"
        return await self._client.get(url, params=params, headers=headers)

    async def post_no_retry(
        self,
        url: str,
        *,
        data: dict[str, str] | None = None,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """POST without retry (used for time-based measurements)."""
        assert self._client is not None, "HTTPClient used outside context manager"
        return await self._client.post(url, data=data, content=content, headers=headers)
