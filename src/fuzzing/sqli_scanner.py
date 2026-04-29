"""SQL Injection scanner: error-based, time-based, and UNION-based detection."""

from __future__ import annotations

import re
import time

from loguru import logger

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.core.rate_limiter import GlobalRateLimiter
from src.vectors.models import AttackVector, VulnType

from .base_scanner import BaseScanner, _format_exc

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

_SQL_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you have an error in your sql syntax",
        r"warning:\s*mysql",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"microsoft ole db provider for sql server",
        r"microsoft sql server.*error",
        r"odbc sql server driver",
        r"odbc.*driver.*error",
        r"sqlite[_\.]?(?:exception|error)",
        r"pg::syntaxerror",
        r"pg::undefinedtable",
        r"postgresql.*error",
        r"org\.postgresql",
        r"ora-\d{4,5}",
        r"db2 sql error",
        r"db2.*sqlcode",
        r"sybase.*sql",
        r"com\.mysql\.jdbc",
        r"java\.sql\.sqlexception",
        r"dynamic sql error",
        r"invalid sql statement",
        r"sql syntax.*?error",
        r"check the manual that corresponds to your (mariadb|mysql) server",
        r"unexpected end of sql command",
        r"supplied argument is not a valid (mysql|postgresql)",
        r"\[mysql\].*error",
        r"\[sqlite\]",
        r"native client.*error",
        r"sqlstate\[",
        r"mysqli?_fetch",
        r"pg_query\(\).*error",
    ]
]

# Marker injected into UNION payloads to confirm data exfiltration.
_UNION_MARKER = "DASTUNION7654321"

# Time-based detection: response must be at least this many ms longer than baseline.
_TIME_THRESHOLD_MS = 4_000

# Typical SLEEP/WAITFOR duration embedded in time-based payloads (seconds).
_SLEEP_DURATION_S = 5


class SQLiScanner(BaseScanner):
    """Detects SQL Injection using error-based, time-based, and UNION-based techniques."""

    VULN_TYPE = VulnType.SQLI

    def __init__(
        self,
        settings: Settings,
        http_client: HTTPClient,
        rate_limiter: GlobalRateLimiter | None = None,
    ) -> None:
        super().__init__(settings, http_client, rate_limiter)

    async def _detect(self, vector: AttackVector, payload: str) -> RawFinding | None:
        """Try one payload and return a finding if a SQLi indicator is detected."""
        try:
            payload_lower = payload.lower()

            # Time-based payloads — must not use automatic retries (timing-sensitive).
            if any(kw in payload_lower for kw in ("sleep(", "waitfor delay", "pg_sleep(")):
                return await self._detect_time_based(vector, payload)

            # UNION-based — look for the exfiltration marker.
            if "union" in payload_lower and _UNION_MARKER.lower() in payload_lower:
                return await self._detect_union(vector, payload)

            # Error-based and boolean-based — look for SQL error messages.
            return await self._detect_error_based(vector, payload)

        except Exception as exc:
            logger.debug(
                "SQLiScanner error on {url} [{field}]: {err}",
                url=vector.target_url,
                field=vector.field_name,
                err=_format_exc(exc),
            )
            return None

    # -------------------------------------------------------------------
    # Detection strategies
    # -------------------------------------------------------------------

    async def _detect_error_based(self, vector: AttackVector, payload: str) -> RawFinding | None:
        response, elapsed = await self._send(vector, payload)
        body = response.text

        for pattern in _SQL_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                evidence = (
                    f"SQL error pattern matched: '{match.group(0)}' (HTTP {response.status_code})"
                )
                logger.debug(
                    "SQLi error-based: {url} [{field}] -> {ev}",
                    url=vector.target_url,
                    field=vector.field_name,
                    ev=evidence,
                )
                return self._make_finding(
                    vector,
                    payload,
                    response,
                    elapsed,
                    Confidence.CONFIRMED,
                    evidence,
                )
        return None

    async def _detect_time_based(self, vector: AttackVector, payload: str) -> RawFinding | None:
        # Measure baseline first.
        try:
            _, baseline_ms = await self._send_baseline(vector)
        except Exception:
            baseline_ms = 0

        # Send time-based payload without retry (timing must not be corrupted).
        t0 = time.monotonic()
        try:
            response, _ = await self._send(vector, payload, no_retry=True)
        except Exception:
            return None
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        expected_delay_ms = _SLEEP_DURATION_S * 1_000
        if elapsed_ms >= (baseline_ms + expected_delay_ms - 500):
            evidence = (
                f"Time-based SQLi: response took {elapsed_ms} ms "
                f"(baseline {baseline_ms} ms, expected delay {expected_delay_ms} ms)"
            )
            logger.debug(
                "SQLi time-based: {url} [{field}] elapsed={t}ms",
                url=vector.target_url,
                field=vector.field_name,
                t=elapsed_ms,
            )
            return self._make_finding(
                vector,
                payload,
                response,
                elapsed_ms,
                Confidence.LIKELY,
                evidence,
            )
        return None

    async def _detect_union(self, vector: AttackVector, payload: str) -> RawFinding | None:
        response, elapsed = await self._send(vector, payload)
        if _UNION_MARKER in response.text:
            evidence = (
                f"UNION-based SQLi: marker '{_UNION_MARKER}' reflected "
                f"in response (HTTP {response.status_code})"
            )
            return self._make_finding(
                vector,
                payload,
                response,
                elapsed,
                Confidence.CONFIRMED,
                evidence,
            )
        return None
