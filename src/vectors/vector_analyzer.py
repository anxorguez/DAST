"""Analyse crawled pages and extract deduplicated attack vectors."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from loguru import logger

from src.vectors.models import AttackVector, CrawledPage, SurfaceType, VulnType

# ---------------------------------------------------------------------------
# Priority heuristics
# ---------------------------------------------------------------------------

# Field names that historically appear in vulnerable injection points.
_HIGH_PRIORITY_NAMES: frozenset[str] = frozenset(
    {
        "id", "user", "username", "name", "query", "q", "search", "keyword",
        "cat", "category", "password", "pass", "email", "file", "filename",
        "path", "cmd", "command", "exec", "order", "sort", "dir", "page",
        "num", "limit", "offset", "table", "column", "field",
    }
)

# These field names suggest OS command execution context — add CMDi.
_CMDI_HINT_NAMES: frozenset[str] = frozenset(
    {
        "cmd", "command", "exec", "execute", "shell", "ping",
        "host", "ip", "file", "filename", "path",
    }
)

# Field types that are not normally injectable (skip them).
_SKIP_TYPES: frozenset[str] = frozenset(
    {"submit", "button", "image", "reset", "file"}
)


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
        logger.info(
            "Vector analysis complete: {n} unique vectors identified", n=len(vectors)
        )
        return vectors

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    def _extract_from_page(self, page: CrawledPage) -> list[AttackVector]:
        vectors: list[AttackVector] = []

        # 1. Vectors from HTML forms
        for form in page.forms:
            for frm_field in form.fields:
                if frm_field.field_type in _SKIP_TYPES:
                    continue

                extra = {
                    f.name: (f.default_value or "")
                    for f in form.fields
                    if f.name != frm_field.name and f.field_type not in _SKIP_TYPES
                }
                vectors.append(
                    AttackVector(
                        source_url=page.url,
                        target_url=form.action_url,
                        method=form.method,
                        surface=SurfaceType.FORM_FIELD,
                        field_name=frm_field.name,
                        field_context=(
                            f"<form action='{form.action_url}' method='{form.method}'>"
                        ),
                        applicable_vulns=self._applicable_vulns(
                            frm_field.name, frm_field.field_type
                        ),
                        priority=self._priority(frm_field.name),
                        extra_params=extra,
                    )
                )

        # 2. Vectors from URL query string parameters
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

    def _applicable_vulns(self, field_name: str, field_type: str) -> list[VulnType]:
        """Determine which vulnerability types to test for this field."""
        lower = field_name.lower()
        vulns: list[VulnType] = [VulnType.SQLI, VulnType.XSS]

        # Hidden fields carry no visual output, so XSS is not meaningful.
        if field_type == "hidden":
            return [VulnType.SQLI]

        # Add CMDi only when field name hints at OS-level execution.
        if any(kw in lower for kw in _CMDI_HINT_NAMES):
            vulns.append(VulnType.CMDI)

        return vulns

    def _priority(self, field_name: str) -> int:
        """Return a priority score: 1 (high) to 3 (low)."""
        lower = field_name.lower()
        if lower in _HIGH_PRIORITY_NAMES:
            return 1
        if any(kw in lower for kw in _HIGH_PRIORITY_NAMES):
            return 2
        return 3
