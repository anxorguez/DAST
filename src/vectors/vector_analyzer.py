"""Analyse crawled pages and extract deduplicated attack vectors."""

from __future__ import annotations

import base64
import re
from urllib.parse import parse_qs, urlparse

from loguru import logger

from src.vectors.models import AttackVector, CrawledPage, SurfaceType, VulnType

# Patterns that suggest a field value contains serialized data.
_SERIALIZED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^rO0AB"),  # Java serialization base64 header
    re.compile(r"^AAEAAAD"),  # .NET BinaryFormatter base64 header
    re.compile(r"^O:\d+:"),  # PHP object serialization
    re.compile(r"^a:\d+:\{"),  # PHP array serialization
]


def _looks_like_serialized(value: str) -> bool:
    """Return True if *value* resembles serialized data."""
    for pat in _SERIALIZED_PATTERNS:
        if pat.search(value):
            return True
    try:
        decoded = base64.b64decode(value + "==")
        if decoded[:2] == b"\xac\xed":  # Java serialization magic
            return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Priority heuristics
# ---------------------------------------------------------------------------

# Field names that historically appear in vulnerable injection points.
_HIGH_PRIORITY_NAMES: frozenset[str] = frozenset(
    {
        "id",
        "user",
        "username",
        "name",
        "query",
        "q",
        "search",
        "keyword",
        "cat",
        "category",
        "password",
        "pass",
        "email",
        "file",
        "filename",
        "path",
        "cmd",
        "command",
        "exec",
        "order",
        "sort",
        "dir",
        "page",
        "num",
        "limit",
        "offset",
        "table",
        "column",
        "field",
    }
)

# These field names suggest OS command execution context — add CMDi.
_CMDI_HINT_NAMES: frozenset[str] = frozenset(
    {
        "cmd",
        "command",
        "exec",
        "execute",
        "shell",
        "ping",
        "host",
        "ip",
        "file",
        "filename",
        "path",
    }
)

# Field names that suggest server-side URL fetching — add SSRF.
_SSRF_HINT_NAMES: frozenset[str] = frozenset(
    {
        "url",
        "endpoint",
        "api",
        "webhook",
        "proxy",
        "fetch",
        "load",
        "src",
        "href",
        "callback",
        "target",
        "dest",
        "destination",
        "image",
        "imageurl",
        "avatar",
        "icon",
    }
)

# Field names that suggest file or path input — add Path Traversal.
_PATH_TRAVERSAL_HINT_NAMES: frozenset[str] = frozenset(
    {
        "file",
        "filename",
        "path",
        "template",
        "include",
        "dir",
        "download",
        "read",
        "load",
        "document",
        "resource",
        "page",
        "view",
        "src",
        "folder",
        "location",
    }
)

# Field names that suggest redirect target — add Open Redirect.
_OPEN_REDIRECT_HINT_NAMES: frozenset[str] = frozenset(
    {
        "url",
        "redirect",
        "next",
        "return",
        "returnto",
        "goto",
        "target",
        "destination",
        "redir",
        "continue",
        "forward",
        "back",
        "ref",
        "referer",
        "return_url",
        "redirect_url",
        "callback",
        "success_url",
        "cancel_url",
    }
)

# Field types that are not normally injectable (skip as fuzz target).
# NOTE: "submit" is intentionally kept out of _SKIP_AS_EXTRA — many PHP apps
# (notably DVWA) gate their vulnerable code behind isset($_GET['Submit']),
# so the submit button's name/value must stay in extra_params for the
# backend to reach the vulnerable branch.
_SKIP_AS_TARGET: frozenset[str] = frozenset({"submit", "button", "image", "reset", "file"})
_SKIP_AS_EXTRA: frozenset[str] = frozenset({"button", "image", "reset", "file"})

# Paths that should never produce attack vectors.  Two motivations:
#   * documentation/help pages (instructions.php, README, *.md) accept a
#     ``doc=...`` parameter that maps to a server-side file include — fuzzing
#     it produces no exploitable signal but can lock up the server reading
#     gigabyte-sized changelogs;
#   * administrative endpoints (security.php, setup.php, phpinfo.php) accept
#     POSTs that mutate global state (DVWA's setup.php truncates the database
#     on each request), so fuzzing them corrupts the target between scans.
#
# Match is case-insensitive against the URL path (basename or full path
# component, depending on the pattern).  Add more paths here as the framework
# is exercised against new applications.
_BLACKLISTED_PATH_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"(^|/)instructions\.php$",
        r"(^|/)phpinfo\.php$",
        r"(^|/)setup\.php$",
        r"(^|/)security\.php$",
        r"(^|/)readme(\.md|\.txt|\.rst)?$",
        r"\.md$",
        r"\.dist$",
        r"(^|/)docker-compose\.ya?ml$",
        r"(^|/)compose\.ya?ml$",
    )
)


def _path_is_blacklisted(url: str) -> bool:
    """Return True if *url*'s path matches any blacklisted pattern."""
    path = urlparse(url).path
    return any(p.search(path) for p in _BLACKLISTED_PATH_PATTERNS)


class VectorAnalyzer:
    """Extracts and deduplicates AttackVector instances from crawled pages."""

    def analyze(self, pages: list[CrawledPage]) -> list[AttackVector]:
        """Return a deduplicated, priority-sorted list of attack vectors.

        Two vectors are considered the same if they share the same
        (target_url, HTTP method, field_name) tuple.
        """
        vectors: list[AttackVector] = []
        seen: set[tuple[str, str, str]] = set()

        for page in pages:
            for vector in self._extract_from_page(page):
                key = (vector.target_url, vector.method, vector.field_name)
                if key not in seen:
                    seen.add(key)
                    vectors.append(vector)

        vectors.sort(key=lambda v: v.priority)
        logger.info("Vector analysis complete: {n} unique vectors identified", n=len(vectors))
        return vectors

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    def _extract_from_page(self, page: CrawledPage) -> list[AttackVector]:
        vectors: list[AttackVector] = []

        # 1. Vectors from HTML forms
        for form in page.forms:
            if _path_is_blacklisted(form.action_url):
                logger.debug(
                    "Vector skipped (blacklisted path): {url}",
                    url=form.action_url,
                )
                continue
            for frm_field in form.fields:
                if frm_field.field_type in _SKIP_AS_TARGET:
                    continue

                extra = {
                    f.name: (f.default_value or "")
                    for f in form.fields
                    if f.name != frm_field.name and f.field_type not in _SKIP_AS_EXTRA
                }
                vectors.append(
                    AttackVector(
                        source_url=page.url,
                        target_url=form.action_url,
                        method=form.method,
                        surface=SurfaceType.FORM_FIELD,
                        field_name=frm_field.name,
                        field_context=(f"<form action='{form.action_url}' method='{form.method}'>"),
                        applicable_vulns=self._applicable_vulns(
                            frm_field.name,
                            frm_field.field_type,
                            default_value=frm_field.default_value,
                            enctype=form.enctype,
                        ),
                        priority=self._priority(frm_field.name),
                        extra_params=extra,
                    )
                )

        # 2. Vectors from URL query string parameters
        if _path_is_blacklisted(page.url):
            logger.debug(
                "URL params skipped (blacklisted path): {url}",
                url=page.url,
            )
            return vectors

        parsed = urlparse(page.url)
        if parsed.query:
            all_params = {
                k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()
            }
            for param_name in all_params:
                extra = {k: v for k, v in all_params.items() if k != param_name}
                vectors.append(
                    AttackVector(
                        source_url=page.url,
                        target_url=page.url,
                        method="GET",
                        surface=SurfaceType.URL_PARAM,
                        field_name=param_name,
                        field_context=f"URL query parameter: {param_name}",
                        applicable_vulns=self._applicable_vulns(param_name, "text"),
                        priority=self._priority(param_name),
                        extra_params=extra,
                    )
                )

        return vectors

    def _applicable_vulns(
        self,
        field_name: str,
        field_type: str,
        default_value: str | None = None,
        enctype: str = "application/x-www-form-urlencoded",
    ) -> list[VulnType]:
        """Determine which vulnerability types to test for this field."""
        lower = field_name.lower()
        vulns: list[VulnType] = [VulnType.SQLI, VulnType.XSS]

        # Hidden fields carry no visual output, so XSS is not meaningful.
        if field_type == "hidden":
            vulns = [VulnType.SQLI]
        # Add CMDi only when field name hints at OS-level execution.
        if any(kw in lower for kw in _CMDI_HINT_NAMES):
            if VulnType.CMDI not in vulns:
                vulns.append(VulnType.CMDI)

        # SSRF: field name suggests URL/endpoint input.
        if any(kw in lower for kw in _SSRF_HINT_NAMES):
            vulns.append(VulnType.SSRF)

        # Path Traversal: field name suggests file/path input.
        if any(kw in lower for kw in _PATH_TRAVERSAL_HINT_NAMES):
            if VulnType.PATH_TRAVERSAL not in vulns:
                vulns.append(VulnType.PATH_TRAVERSAL)

        # Open Redirect: field name suggests redirect target.
        if any(kw in lower for kw in _OPEN_REDIRECT_HINT_NAMES):
            if VulnType.OPEN_REDIRECT not in vulns:
                vulns.append(VulnType.OPEN_REDIRECT)

        # XXE: only when the form enctype is XML or field appears to accept XML.
        xml_enctypes = ("application/xml", "text/xml", "application/soap+xml")
        if any(enc in enctype.lower() for enc in xml_enctypes):
            vulns.append(VulnType.XXE)

        # Deserialization: field default value looks like serialized data.
        if default_value and _looks_like_serialized(default_value):
            vulns.append(VulnType.DESERIALIZATION)

        return vulns

    def _priority(self, field_name: str) -> int:
        """Return a priority score: 1 (high) to 3 (low)."""
        lower = field_name.lower()
        if lower in _HIGH_PRIORITY_NAMES:
            return 1
        if any(kw in lower for kw in _HIGH_PRIORITY_NAMES):
            return 2
        return 3
