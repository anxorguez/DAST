"""Manages the Playwright browser lifecycle."""

from __future__ import annotations

from playwright.async_api import (
    Browser,
    BrowserContext,
    Playwright,
    async_playwright,
)


class BrowserManager:
    """Async context manager that owns a Playwright Chromium browser instance.

    Usage::

        async with BrowserManager(headless=True, timeout_ms=30_000) as manager:
            context = await manager.new_context()
            page = await context.new_page()
            ...
    """

    def __init__(self, headless: bool = True, timeout_ms: int = 30_000) -> None:
        self._headless = headless
        self._timeout_ms = timeout_ms
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None

    async def __aenter__(self) -> BrowserManager:
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self._headless,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-extensions",
            ],
        )
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    async def new_context(self) -> BrowserContext:
        """Create a new isolated browser context with HTTPS error tolerance."""
        assert self._browser is not None, "BrowserManager used outside context manager"
        context = await self._browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True,
        )
        context.set_default_timeout(self._timeout_ms)
        return context
