"""Extract internal hyperlinks from a rendered HTML page."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Tag

# Links that, if followed, would invalidate the authenticated session.
# The crawler must not follow these during BFS or every subsequent page
# will redirect to the login form and no vectors will be discoverable.
_SESSION_KILLING_PATH_RE: re.Pattern[str] = re.compile(
    r"/(logout|signout|sign-out|log-out|exit)(\.php|\.aspx|\.jsp|/|$)",
    re.IGNORECASE,
)


def extract_links(html: str, base_url: str, target_hostname: str) -> list[str]:
    """Return all internal <a href> links found in *html*.

    Only links whose hostname matches *target_hostname* are returned.
    Fragment identifiers are stripped, and duplicates removed.

    Args:
        html: Fully rendered HTML content.
        base_url: Canonical URL of the current page (used for relative URLs).
        target_hostname: The hostname that defines the crawling boundary.

    Returns:
        Deduplicated list of absolute, same-domain URLs.
    """
    soup = BeautifulSoup(html, "lxml")
    seen: set[str] = set()
    links: list[str] = []

    for tag in soup.find_all("a", href=True):
        if not isinstance(tag, Tag):
            continue

        href = str(tag["href"]).strip()

        # Skip non-HTTP schemes
        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue

        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)

        # Enforce same-domain boundary
        if parsed.hostname != target_hostname:
            continue

        # Skip session-destroying links (logout, signout) so the crawler
        # does not log itself out midway and lose access to the rest of
        # the authenticated surface.
        if _SESSION_KILLING_PATH_RE.search(parsed.path):
            continue

        # Strip fragment and normalise
        clean = parsed._replace(fragment="").geturl()

        if clean not in seen:
            seen.add(clean)
            links.append(clean)

    return links
