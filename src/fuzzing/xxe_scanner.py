"""XXE (XML External Entity) scanner: file read and parser-error detection."""

from __future__ import annotations

import re

from loguru import logger

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.vectors.models import AttackVector, VulnType

from .base_scanner import BaseScanner

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

# Content patterns indicating the server resolved an external entity.
_FILE_CONTENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"root:x:\d+:\d+:",         # /etc/passwd
        r"daemon:x:\d+:\d+:",
        r"\[boot loader\]",          # boot.ini
        r"\[extensions\]",           # win.ini
        r"\[fonts\]",                # win.ini
        r"127\.0\.0\.1\s+localhost", # /etc/hosts
        r"AWS_SECRET_ACCESS_KEY",
        r"AWS_ACCESS_KEY_ID",
        r"ami-id",                   # AWS metadata
    ]
]

# Parser error patterns (LIKELY: entity processing triggered an exception).
_XML_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"SAXParseException",
        r"XMLSyntaxError",
        r"lxml\.etree",
        r"javax\.xml",
        r"org\.xml\.sax",
        r"com\.sun\.org\.apache",
        r"xml\.etree\.ElementTree",
        r"xmlParseEntityRef",
        r"invalid entity reference",
        r"undefined entity",
        r"entity.*not defined",
        r"DOCTYPE is disallowed",
        r"external entity",
        r"SYSTEM.*not allowed",
        r"DTD.*prohibited",
    ]
]

# XML Content-Type values that indicate the endpoint accepts XML.
_XML_CONTENT_TYPES = (
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/soap+xml",
)


class XXEScanner(BaseScanner):
    """Detects XXE injection by sending malicious DTD payloads via XML body.

    Only runs against vectors whose surface suggests XML input.
    """

    VULN_TYPE = VulnType.XXE

    def __init__(self, settings: Settings, http_client: HTTPClient) -> None:
        super().__init__(settings, http_client)

    async def _detect(
        self, vector: AttackVector, payload: str
    ) -> RawFinding | None:
        """Send an XML payload and check for entity resolution or parser errors."""
        try:
            # Send payload as XML body regardless of the vector's default
            # content-type; the scanner overrides Content-Type in the request.
            response, elapsed = await self._send_xml(vector, payload)
            body = response.text

            # Strategy 1: file content resolved by the parser (CONFIRMED).
            for pattern in _FILE_CONTENT_PATTERNS:
                match = pattern.search(body)
                if match:
                    evidence = (
                        f"XXE: file content '{match.group(0)}' reflected in "
                        f"response (HTTP {response.status_code}) — external "
                        f"entity was resolved."
                    )
                    logger.debug(
                        "XXE confirmed: {url} [{field}]",
                        url=vector.target_url,
                        field=vector.field_name,
                    )
                    return self._make_finding(
                        vector, payload, response, elapsed,
                        Confidence.CONFIRMED, evidence,
                    )

            # Strategy 2: XML parser error — entity processing attempted (LIKELY).
            for pattern in _XML_ERROR_PATTERNS:
                match = pattern.search(body)
                if match:
                    evidence = (
                        f"XXE: XML parser error '{match.group(0)}' — DTD/entity "
                        f"processing triggered (HTTP {response.status_code})."
                    )
                    logger.debug(
                        "XXE likely: {url} [{field}] parser_error='{e}'",
                        url=vector.target_url,
                        field=vector.field_name,
                        e=match.group(0),
                    )
                    return self._make_finding(
                        vector, payload, response, elapsed,
                        Confidence.LIKELY, evidence,
                    )

        except Exception as exc:
            logger.debug(
                "XXEScanner error on {url} [{field}]: {err}",
                url=vector.target_url,
                field=vector.field_name,
                err=exc,
            )

        return None

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    async def _send_xml(
        self, vector: AttackVector, payload: str
    ) -> tuple[object, int]:
        """Send the XML payload with an appropriate Content-Type header.

        Uses post_no_retry because XXE probes are timing-insensitive and
        we don't want to trigger WAF rate-limiting with retries.
        """
        import time

        import httpx

        headers = {"Content-Type": "application/xml; charset=utf-8"}

        start = time.monotonic()
        try:
            response = await self._http.post_no_retry(
                vector.target_url,
                data=payload.encode("utf-8"),  # type: ignore[arg-type]
                headers=headers,  # type: ignore[arg-type]
            )
        except Exception:
            # Fall back to field injection if the XML post failed.
            response, _ = await self._send(vector, payload)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return response, elapsed_ms
