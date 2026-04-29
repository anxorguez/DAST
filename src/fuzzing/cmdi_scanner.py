"""Command Injection scanner: error-based and time-based detection."""

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
# Detection signatures — command output patterns
# ---------------------------------------------------------------------------

_UNIX_OUTPUT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"uid=\d+\(",  # id output: uid=0(root)
        r"gid=\d+\(",  # id output: gid=0(root)
        r"root:x:\d+:\d+:",  # /etc/passwd line
        r"/bin/(sh|bash|dash|zsh)",
        r"/usr/bin/",
        r"/etc/passwd",
        r"/etc/shadow",
        r"command not found",
        r"permission denied",
        r"no such file or directory",
        r"sh: \d+:",
        r"\$\s*$",  # Shell prompt artifact
    ]
]

_WINDOWS_OUTPUT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"volume in drive [a-z] (has no label|is)",
        r"volume serial number",
        r"directory of [a-z]:\\",
        r"windows ip configuration",
        r"ipconfig",
        r"nt authority\\system",
        r"microsoft windows \[version",
        r"c:\\windows\\system32",
        r"'.*' is not recognized as an internal or external command",
    ]
]

_ALL_CMDI_PATTERNS = _UNIX_OUTPUT_PATTERNS + _WINDOWS_OUTPUT_PATTERNS

# Time-based detection parameters
_TIME_THRESHOLD_MS = 4_000
_SLEEP_DURATION_S = 5


class CMDiScanner(BaseScanner):
    """Detects Command Injection using error-based output patterns and time-based delays."""

    VULN_TYPE = VulnType.CMDI

    def __init__(
        self,
        settings: Settings,
        http_client: HTTPClient,
        rate_limiter: GlobalRateLimiter | None = None,
    ) -> None:
        super().__init__(settings, http_client, rate_limiter)

    async def _detect(self, vector: AttackVector, payload: str) -> RawFinding | None:
        """Try one payload; return a finding if CMDi evidence is found."""
        try:
            payload_lower = payload.lower()

            # Time-based payloads (sleep / ping -c N / ping -n N)
            if any(kw in payload_lower for kw in ("sleep ", "ping -c", "ping -n")):
                return await self._detect_time_based(vector, payload)

            # Error-based / output-based
            return await self._detect_error_based(vector, payload)

        except Exception as exc:
            logger.debug(
                "CMDiScanner error on {url} [{field}]: {err}",
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

        for pattern in _ALL_CMDI_PATTERNS:
            match = pattern.search(body)
            if match:
                evidence = (
                    f"CMDi output pattern matched: '{match.group(0)}' (HTTP {response.status_code})"
                )
                logger.debug(
                    "CMDi error-based: {url} [{field}] -> {ev}",
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
        try:
            _, baseline_ms = await self._send_baseline(vector)
        except Exception:
            baseline_ms = 0

        t0 = time.monotonic()
        try:
            response, _ = await self._send(vector, payload, no_retry=True)
        except Exception:
            return None
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        expected_delay_ms = _SLEEP_DURATION_S * 1_000
        if elapsed_ms >= (baseline_ms + expected_delay_ms - 500):
            evidence = (
                f"Time-based CMDi: response took {elapsed_ms} ms "
                f"(baseline {baseline_ms} ms, expected delay {expected_delay_ms} ms)"
            )
            logger.debug(
                "CMDi time-based: {url} [{field}] elapsed={t}ms",
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
