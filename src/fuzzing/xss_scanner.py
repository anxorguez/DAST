"""XSS scanner: reflected and DOM-based detection via payload reflection analysis."""

from __future__ import annotations

import html as html_lib
import re

import httpx
from loguru import logger

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.core.rate_limiter import GlobalRateLimiter
from src.vectors.models import AttackVector, VulnType

from .base_scanner import BaseScanner, _format_exc

# ---------------------------------------------------------------------------
# Patterns that indicate the payload was reflected without encoding.
# ---------------------------------------------------------------------------

# Patterns that indicate JS execution context in the payload.
_EXEC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+=", re.IGNORECASE),
    re.compile(r"<svg[\s/]", re.IGNORECASE),
    re.compile(r"<img\s+[^>]*onerror", re.IGNORECASE),
]

# Discriminating XSS shapes: these fragments, when newly present in a response,
# are strong evidence of reflection. They are narrow enough that a benign page
# (even one containing <img> or <body>) is unlikely to match.
#
#   - <tag ... on*=...          (any tag bearing an inline event handler)
#   - <script ...>              (script tag opener)
#   - javascript:<expr>         (javascript: pseudo-URL with a following token)
_DISCRIMINATING_PAYLOAD_RE: re.Pattern[str] = re.compile(
    r"<\w+\b[^>]*\bon\w+\s*=[^>]*|<script\b[^>]*>|javascript:[A-Za-z_][\w.]*",
    re.IGNORECASE,
)


class XSSScanner(BaseScanner):
    """Detects reflected and DOM-based XSS by analysing HTTP response content."""

    VULN_TYPE = VulnType.XSS

    def __init__(
        self,
        settings: Settings,
        http_client: HTTPClient,
        rate_limiter: GlobalRateLimiter | None = None,
    ) -> None:
        super().__init__(settings, http_client, rate_limiter)
        # Baseline cache: body text of a benign request per vector.id.
        # A value of None means the baseline fetch failed and Strategy 2 must be skipped.
        self._baseline_cache: dict[str, str | None] = {}

    async def _detect(self, vector: AttackVector, payload: str) -> RawFinding | None:
        """Send *payload*, check if it appears unescaped in the response."""
        try:
            baseline_body = await self._get_baseline(vector)
            response, elapsed = await self._send(vector, payload)
            body = response.text

            finding = self._check_reflection(
                vector, payload, body, baseline_body, response, elapsed
            )
            if finding:
                logger.debug(
                    "XSS reflected: {url} [{field}]",
                    url=vector.target_url,
                    field=vector.field_name,
                )
            return finding

        except Exception as exc:
            logger.debug(
                "XSSScanner error on {url} [{field}]: {err}",
                url=vector.target_url,
                field=vector.field_name,
                err=_format_exc(exc),
            )
            return None

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    async def _get_baseline(self, vector: AttackVector) -> str | None:
        """Fetch (and cache) a benign baseline response body for *vector*.

        The baseline is used by Strategy 2 to distinguish native page content
        from genuinely reflected payload fragments. Returns None if the
        baseline request fails, in which case Strategy 2 is skipped entirely
        to avoid false positives.
        """
        if vector.id in self._baseline_cache:
            return self._baseline_cache[vector.id]
        try:
            response, _ = await self._send_baseline(vector)
            self._baseline_cache[vector.id] = response.text
        except Exception as exc:
            logger.debug(
                "XSS baseline fetch failed for {url} [{field}]: {err}",
                url=vector.target_url,
                field=vector.field_name,
                err=_format_exc(exc),
            )
            self._baseline_cache[vector.id] = None
        return self._baseline_cache[vector.id]

    def _check_reflection(
        self,
        vector: AttackVector,
        payload: str,
        body: str,
        baseline_body: str | None,
        response: httpx.Response,
        elapsed: int,
    ) -> RawFinding | None:
        # Strategy 1: exact payload string appears verbatim in response body.
        if payload in body:
            # Verify it is not HTML-escaped — unescape and look for it again.
            unescaped_body = html_lib.unescape(body)
            if payload in unescaped_body:
                confidence = self._assess_confidence(payload, body)
                evidence = (
                    f"XSS payload reflected verbatim in HTTP {response.status_code} "
                    f"response (unescaped)"
                )
                return self._make_finding(vector, payload, response, elapsed, confidence, evidence)

        # Strategy 2: discriminating XSS shapes from the payload appear in the
        # response more often than in a benign baseline. Without a baseline we
        # cannot distinguish native page content from reflection, so we skip.
        if baseline_body is None:
            return None

        body_lower = body.lower()
        baseline_lower = baseline_body.lower()

        for part in self._extract_key_parts(payload):
            part_lower = part.lower()
            body_count = body_lower.count(part_lower)
            baseline_count = baseline_lower.count(part_lower)
            if body_count > baseline_count:
                evidence = (
                    f"XSS payload component '{self._truncate(part, 80)}' reflected "
                    f"unencoded in response (baseline occurrences: {baseline_count}, "
                    f"response occurrences: {body_count})"
                )
                return self._make_finding(
                    vector,
                    payload,
                    response,
                    elapsed,
                    Confidence.LIKELY,
                    evidence,
                )

        return None

    def _assess_confidence(self, payload: str, body: str) -> Confidence:
        """Return CONFIRMED if the payload contains an executable construct."""
        for pattern in _EXEC_PATTERNS:
            if pattern.search(payload):
                return Confidence.CONFIRMED
        return Confidence.LIKELY

    def _extract_key_parts(self, payload: str) -> list[str]:
        """Extract discriminating XSS shapes from *payload* for partial matching.

        Only returns fragments that would not normally appear in a benign page:
        tag+event-handler pairs, ``<script`` openers, and ``javascript:`` URIs.
        Bare tag names like ``<img`` or ``<body`` are deliberately excluded
        because they appear natively in most HTML pages and caused false
        positives in earlier versions.
        """
        return [m.group(0) for m in _DISCRIMINATING_PAYLOAD_RE.finditer(payload)]
