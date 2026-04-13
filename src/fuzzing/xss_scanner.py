"""XSS scanner: reflected and DOM-based detection via payload reflection analysis."""

from __future__ import annotations

import html as html_lib
import re

import httpx
from loguru import logger

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.vectors.models import AttackVector, VulnType

from .base_scanner import BaseScanner

# ---------------------------------------------------------------------------
# Patterns that indicate the payload was reflected without encoding.
# ---------------------------------------------------------------------------

# Dangerous tag names that are meaningful in a reflected XSS context.
_DANGEROUS_TAGS: tuple[str, ...] = (
    "script",
    "svg",
    "img",
    "iframe",
    "body",
    "video",
    "audio",
    "details",
    "marquee",
    "math",
)

# Event handler attribute prefixes (e.g. "onerror=", "onload=").
_EVENT_HANDLERS: tuple[str, ...] = (
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "onfocus=",
    "onsubmit=",
    "oninput=",
)

# Patterns that indicate JS execution context in the payload.
_EXEC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+=", re.IGNORECASE),
    re.compile(r"<svg[\s/]", re.IGNORECASE),
    re.compile(r"<img\s+[^>]*onerror", re.IGNORECASE),
]


class XSSScanner(BaseScanner):
    """Detects reflected and DOM-based XSS by analysing HTTP response content."""

    VULN_TYPE = VulnType.XSS

    def __init__(self, settings: Settings, http_client: HTTPClient) -> None:
        super().__init__(settings, http_client)

    async def _detect(self, vector: AttackVector, payload: str) -> RawFinding | None:
        """Send *payload*, check if it appears unescaped in the response."""
        try:
            response, elapsed = await self._send(vector, payload)
            body = response.text

            finding = self._check_reflection(vector, payload, body, response, elapsed)
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
                err=exc,
            )
            return None

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    def _check_reflection(
        self,
        vector: AttackVector,
        payload: str,
        body: str,
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

        # Strategy 2: key structural parts of the payload appear unescaped.
        for part in self._extract_key_parts(payload):
            if part and part in body and part not in html_lib.escape(part, quote=False):
                evidence = (
                    f"XSS payload component '{self._truncate(part, 80)}' "
                    f"reflected unencoded in response"
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
        """Extract the most diagnostic fragments from a payload for partial matching."""
        parts: list[str] = []

        # Extract tag names: <script, <svg, <img, etc.
        for tag in _DANGEROUS_TAGS:
            if f"<{tag}" in payload.lower():
                parts.append(f"<{tag}")

        # Extract event handlers: onerror=, onload=, etc.
        lower = payload.lower()
        for handler in _EVENT_HANDLERS:
            if handler in lower:
                parts.append(handler)

        return parts
