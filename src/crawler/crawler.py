"""Core crawler: BFS navigation with Playwright + optional pre-authentication."""

from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import Any
from urllib.parse import urljoin, urlparse

from loguru import logger
from playwright.async_api import BrowserContext, Page, Request

from src.analysis.models import CrawlStats
from src.core.config import Settings
from src.core.exceptions import AuthenticationError
from src.vectors.models import CrawledPage

from .browser_manager import BrowserManager
from .form_extractor import extract_forms
from .link_extractor import extract_links

# File extensions that trigger a browser download instead of an HTML render.
# Visiting these wastes a Playwright tab and produces a ``Download is starting``
# warning per URL — there is no HTML for the form/link extractors to chew on,
# so we skip them up-front.  Match against the URL path (lowercased), not the
# full URL, to avoid being confused by query strings.
_DOWNLOAD_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pdf",
        ".zip",
        ".tar",
        ".tar.gz",
        ".tgz",
        ".gz",
        ".rar",
        ".7z",
        ".exe",
        ".dmg",
        ".iso",
        ".msi",
        ".deb",
        ".rpm",
        ".dist",
        ".jar",
        ".war",
        ".bin",
        ".apk",
    }
)


def _is_download_url(url: str) -> bool:
    """Return True if *url* points to a file that would trigger a download."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return any(path.endswith(ext) for ext in _DOWNLOAD_EXTENSIONS)


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
        # Cookies captured from the authenticated browser context after crawl().
        # Consumers (e.g. the Fuzzer's HTTPClient) use these to inherit the
        # session established by pre-scan login. Each entry is Playwright's
        # cookie dict: {name, value, domain, path, ...}.
        self._session_cookies: list[dict[str, Any]] = []
        # Why the crawl stopped — populated by ``_bfs_crawl`` and read by
        # the pipeline so the report can distinguish "max-pages reached"
        # from "frontier exhausted" and the analyst can tell whether
        # raising the knob would help.
        self._crawl_stats = CrawlStats()

    @property
    def session_cookies(self) -> list[dict[str, Any]]:
        """Cookies captured from the authenticated browser context after crawl().

        Empty if authentication was not enabled or crawl() has not yet run.
        """
        return list(self._session_cookies)

    @property
    def crawl_stats(self) -> CrawlStats:
        """Diagnostics about why the BFS crawl stopped (see :class:`CrawlStats`)."""
        return self._crawl_stats

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
                    await self._set_dvwa_security_level(context)
                    # Capture cookies *immediately* after authenticating and
                    # before the BFS crawl. The BFS may follow destructive
                    # links such as /logout.php which silently invalidate the
                    # server-side session — if we captured afterwards, the
                    # Fuzzer would inherit an unauthenticated cookie and every
                    # request would bounce back to the login page.
                    raw_cookies = await context.cookies()
                    self._session_cookies = [dict(c) for c in raw_cookies]

                pages = await self._bfs_crawl(context)
                logger.info(
                    "Crawl complete: visited {n} pages | session cookies captured: {c}",
                    n=len(pages),
                    c=len(self._session_cookies),
                )
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
                    await self._set_dvwa_security_level(context)

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

            # DVWA redirects to /setup.php before the login form when the DB is not
            # initialised, or on the first browser visit after a fresh DB creation.
            if "setup.php" in page.url:
                logger.info("DVWA setup.php detected before login — initialising database")
                await self._dvwa_db_init(page)
                await page.goto(s.auth_url, wait_until="domcontentloaded")

            username_selector = f"[name='{s.auth_username_field}']"
            password_selector = f"[name='{s.auth_password_field}']"

            await page.fill(username_selector, s.auth_username)
            await page.fill(password_selector, s.auth_password)
            await page.press(password_selector, "Enter")
            await page.wait_for_load_state("networkidle")

            # DVWA can redirect to /setup.php on the first login after a fresh DB
            # initialisation even when the tables already exist.
            if "setup.php" in page.url:
                logger.info("DVWA setup.php detected after login — re-initialising database")
                await self._dvwa_db_init(page)
                await page.goto(s.auth_url, wait_until="domcontentloaded")
                await page.fill(username_selector, s.auth_username)
                await page.fill(password_selector, s.auth_password)
                await page.press(password_selector, "Enter")
                await page.wait_for_load_state("networkidle")

            if s.auth_success_url:
                current = page.url
                if s.auth_success_url not in current:
                    raise AuthenticationError(
                        f"Login redirect verification failed. "
                        f"Expected URL containing '{s.auth_success_url}', got '{current}'. "
                        f"If using DVWA, the database may not be initialised — "
                        f"visit /setup.php?setupDatabase=1 before running the scan."
                    )

            logger.info("Pre-scan authentication successful")
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError(f"Authentication error: {exc}") from exc
        finally:
            await page.close()

    async def _dvwa_db_init(self, page: Page) -> None:
        """Submit DVWA's 'Create / Reset Database' form via Playwright.

        Called automatically when /setup.php is detected during authentication.
        Uses the browser session so PHP session state is consistent.
        """
        setup_url = urljoin(self._settings.target_url, "/setup.php")
        if "setup.php" not in page.url:
            await page.goto(setup_url, wait_until="domcontentloaded")
        try:
            await page.click("input[name='create_db']", timeout=5000)
            await page.wait_for_load_state("networkidle", timeout=30000)
            logger.info("DVWA database initialised via browser session")
        except Exception as exc:
            logger.debug("DVWA create_db click failed (may already be ready): {e}", e=exc)

    async def _set_dvwa_security_level(self, context: BrowserContext) -> None:
        """Best-effort: set DVWA's security level on the authenticated session.

        DVWA defaults to the 'impossible' security level after login, which
        disables every intentional vulnerability. For a scan to find anything
        the level must be lowered. This step submits the form at /security.php
        and logs silently if the endpoint is absent (target is not DVWA).
        """
        level = self._settings.dvwa_security_level
        if not level:
            return

        security_url = urljoin(self._settings.target_url, "/security.php")
        page = await context.new_page()
        try:
            await page.goto(security_url, wait_until="domcontentloaded")
            if "security.php" not in page.url:
                # Redirected elsewhere — the target is probably not DVWA.
                logger.debug(
                    "Skipping DVWA security level (no /security.php at {u})",
                    u=security_url,
                )
                return
            await page.select_option("select[name='security']", level)
            await page.click("input[name='seclev_submit']")
            await page.wait_for_load_state("networkidle", timeout=5_000)
            logger.info("DVWA security level set to '{l}'", l=level)
        except Exception as exc:
            logger.debug(
                "Could not set DVWA security level (target may not be DVWA): {err}",
                err=exc,
            )
        finally:
            try:
                await page.close()
            except Exception:
                pass

    async def _bfs_crawl(self, context: BrowserContext) -> list[CrawledPage]:
        """Breadth-first traversal starting from TARGET_URL."""
        queue: deque[tuple[str, int]] = deque([(self._settings.target_url, 0)])
        crawled: list[CrawledPage] = []
        in_queue: set[str] = {self._settings.target_url}
        hit_max_pages = False

        while queue and len(crawled) < self._settings.max_pages:
            url, depth = queue.popleft()

            if url in self._visited:
                continue
            if depth > self._settings.max_depth:
                continue
            if _is_download_url(url):
                # Skip silently: these URLs trigger a Playwright download
                # event that surfaces as a noisy ``WARNING ... Download is
                # starting`` for every PDF/ZIP/etc. linked from the target.
                logger.debug("Skipping download URL: {url}", url=url)
                self._visited.add(url)
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

        # Decide why we stopped.  Three buckets:
        #   * frontier_exhausted — the queue ran dry (target fully discovered
        #     within the configured limits).  Raising max_pages won't help.
        #   * max_pages_reached — we hit the page cap and there were still
        #     URLs to visit.  Raising max_pages would discover more.
        #   * max_depth_reached — only entries deeper than max_depth remain.
        #     Raising max_depth (not max_pages) would discover more.
        if len(crawled) >= self._settings.max_pages and queue:
            hit_max_pages = True

        unvisited = [(u, d) for (u, d) in queue if u not in self._visited]
        if hit_max_pages:
            self._crawl_stats.crawl_limit_reason = "max_pages_reached"
        elif unvisited and all(d > self._settings.max_depth for _, d in unvisited):
            self._crawl_stats.crawl_limit_reason = "max_depth_reached"
        else:
            self._crawl_stats.crawl_limit_reason = "frontier_exhausted"
        self._crawl_stats.queued_unvisited = len(unvisited)

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
            # ``Page.goto: Download is starting`` is benign — we already
            # filter known download extensions before the goto, but some
            # apps (DVWA's docs/, config.inc.php.dist) trigger downloads
            # via Content-Disposition without a recognisable extension.
            # Don't pollute the WARN tier for those.
            err_msg = str(exc)
            if "Download is starting" in err_msg:
                logger.debug(
                    "Skipping {url} (server returned a download): {err}",
                    url=url,
                    err=err_msg,
                )
            else:
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
