"""Core crawler: BFS navigation with Playwright + optional pre-authentication."""

from __future__ import annotations

from collections import deque
from datetime import datetime
from urllib.parse import urlparse

from loguru import logger
from playwright.async_api import BrowserContext, Page, Request

from src.core.config import Settings
from src.core.exceptions import AuthenticationError
from src.vectors.models import CrawledPage

from .browser_manager import BrowserManager
from .form_extractor import extract_forms
from .link_extractor import extract_links

# ---------------------------------------------------------------------------
# Stored-XSS hit — lightweight struct used between crawler and pipeline.
# ---------------------------------------------------------------------------


class StoredXSSHit:
    """Represents a stored XSS payload found in the DOM during the second pass."""

    __slots__ = ("page_url", "payload", "evidence_snippet")

    def __init__(self, page_url: str, payload: str, evidence_snippet: str) -> None:
        self.page_url = page_url
        self.payload = payload
        self.evidence_snippet = evidence_snippet


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------


class Crawler:
    """Performs a BFS crawl of the target application using Playwright.

    The crawler respects MAX_DEPTH and MAX_PAGES configuration limits and
    never follows URLs outside the target hostname. An optional pre-authentication
    step logs in via a form before the main crawl begins.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        parsed = urlparse(settings.target_url)
        self._target_hostname = parsed.hostname or ""
        self._visited: set[str] = set()

    # -------------------------------------------------------------------
    # Public interface
    # -------------------------------------------------------------------

    async def crawl(self) -> list[CrawledPage]:
        """Perform the full BFS crawl and return all visited pages.

        Returns:
            List of CrawledPage objects in visit order.

        Raises:
            CrawlerError: If the start URL cannot be reached.
        """
        timeout_ms = self._settings.request_timeout * 1000

        async with BrowserManager(headless=True, timeout_ms=timeout_ms) as manager:
            context = await manager.new_context()
            try:
                if self._settings.auth_enabled:
                    await self._authenticate(context)

                pages = await self._bfs_crawl(context)
                logger.info("Crawl complete: visited {n} pages", n=len(pages))
                return pages
            finally:
                await context.close()

    async def second_pass(self, xss_payloads: list[str]) -> list[StoredXSSHit]:
        """Re-crawl the site looking for stored XSS payloads in the DOM.

        Args:
            xss_payloads: List of XSS payload strings that were injected during fuzzing.

        Returns:
            List of StoredXSSHit instances where a payload was found unescaped.
        """
        if not xss_payloads:
            return []

        timeout_ms = self._settings.request_timeout * 1000
        hits: list[StoredXSSHit] = []

        async with BrowserManager(headless=True, timeout_ms=timeout_ms) as manager:
            context = await manager.new_context()
            try:
                if self._settings.auth_enabled:
                    await self._authenticate(context)

                urls_to_check = list(self._visited) or [self._settings.target_url]

                for url in urls_to_check:
                    page_hits = await self._check_stored_xss(context, url, xss_payloads)
                    hits.extend(page_hits)
            finally:
                await context.close()

        logger.info(
            "Stored XSS second pass: {n} hit(s) found across {p} page(s)",
            n=len(hits),
            p=len(self._visited),
        )
        return hits

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    async def _authenticate(self, context: BrowserContext) -> None:
        """Submit the login form and verify redirection to the success URL."""
        s = self._settings
        if not s.auth_url:
            raise AuthenticationError("auth_enabled=true but AUTH_URL is not set.")

        page = await context.new_page()
        try:
            await page.goto(s.auth_url, wait_until="domcontentloaded")

            username_selector = f"[name='{s.auth_username_field}']"
            password_selector = f"[name='{s.auth_password_field}']"

            await page.fill(username_selector, s.auth_username)
            await page.fill(password_selector, s.auth_password)
            await page.press(password_selector, "Enter")
            await page.wait_for_load_state("networkidle")

            if s.auth_success_url:
                current = page.url
                if s.auth_success_url not in current:
                    raise AuthenticationError(
                        f"Login redirect verification failed. "
                        f"Expected URL containing '{s.auth_success_url}', got '{current}'."
                    )

            logger.info("Pre-scan authentication successful")
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError(f"Authentication error: {exc}") from exc
        finally:
            await page.close()

    async def _bfs_crawl(self, context: BrowserContext) -> list[CrawledPage]:
        """Breadth-first traversal starting from TARGET_URL."""
        queue: deque[tuple[str, int]] = deque([(self._settings.target_url, 0)])
        crawled: list[CrawledPage] = []
        in_queue: set[str] = {self._settings.target_url}

        while queue and len(crawled) < self._settings.max_pages:
            url, depth = queue.popleft()

            if url in self._visited:
                continue
            if depth > self._settings.max_depth:
                continue

            self._visited.add(url)

            page = await self._visit_page(context, url, depth)
            if page is None:
                continue

            crawled.append(page)

            for link in page.internal_links:
                if link not in self._visited and link not in in_queue:
                    in_queue.add(link)
                    queue.append((link, depth + 1))

        return crawled

    async def _visit_page(
        self, context: BrowserContext, url: str, depth: int
    ) -> CrawledPage | None:
        """Visit a single URL and return a CrawledPage, or None on error."""
        xhr_endpoints: list[str] = []
        page: Page | None = None

        try:
            page = await context.new_page()

            def _capture_xhr(request: Request) -> None:
                if request.resource_type in ("xhr", "fetch"):
                    xhr_endpoints.append(request.url)

            page.on("request", _capture_xhr)

            timeout_ms = self._settings.request_timeout * 1000
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

            # Brief wait for JS rendering; ignore timeout here (best effort).
            try:
                await page.wait_for_load_state("networkidle", timeout=5_000)
            except Exception:
                pass

            html = await page.content()
            forms = extract_forms(html, url)
            links = extract_links(html, url, self._target_hostname)

            logger.debug(
                "Visited {url} depth={d} forms={f} links={l}",
                url=url,
                d=depth,
                f=len(forms),
                l=len(links),
            )

            return CrawledPage(
                url=url,
                html_content=html,
                forms=forms,
                internal_links=links,
                xhr_endpoints=xhr_endpoints,
                depth=depth,
                crawled_at=datetime.utcnow(),
            )

        except Exception as exc:
            logger.warning("Could not crawl {url}: {err}", url=url, err=exc)
            return None
        finally:
            if page is not None:
                try:
                    await page.close()
                except Exception:
                    pass

    async def _check_stored_xss(
        self,
        context: BrowserContext,
        url: str,
        payloads: list[str],
    ) -> list[StoredXSSHit]:
        """Load a URL and search its rendered DOM for injected XSS payloads."""
        hits: list[StoredXSSHit] = []
        page: Page | None = None

        try:
            page = await context.new_page()
            timeout_ms = self._settings.request_timeout * 1000
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

            try:
                await page.wait_for_load_state("networkidle", timeout=5_000)
            except Exception:
                pass

            content = await page.content()

            for payload in payloads:
                if payload in content:
                    # Extract a short surrounding snippet
                    idx = content.find(payload)
                    start = max(0, idx - 60)
                    end = min(len(content), idx + len(payload) + 60)
                    snippet = content[start:end]
                    hits.append(StoredXSSHit(url, payload, snippet))
                    logger.debug("Stored XSS payload found in {url}", url=url)

        except Exception as exc:
            logger.debug("Second-pass error for {url}: {err}", url=url, err=exc)
        finally:
            if page is not None:
                try:
                    await page.close()
                except Exception:
                    pass

        return hits
