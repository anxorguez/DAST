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
#
# Patterns are matched against the full response body with IGNORECASE and
# MULTILINE.  MULTILINE is required because DVWA-style targets wrap output in
# a ``<pre>...</pre>`` block, so the start-of-line anchor ``^`` must match
# inside the pre block, not only at byte 0 of the document.
#
# When extending the lists, prefer signatures with embedded structure
# (digits, colons, parentheses, dotted-quad addresses) over plain words —
# those resist false positives from menu items / nav links that happen to
# share a vocabulary with shell command output.

_UNIX_OUTPUT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE | re.MULTILINE)
    for p in [
        # id / whoami style
        r"uid=\d+\(",  # id output: uid=0(root)
        r"gid=\d+\(",  # id output: gid=0(root)
        r"groups=\d+\(",  # id output: groups=33(www-data)
        # /etc/passwd / /etc/shadow leakage
        r"^(?:root|daemon|bin|sys|nobody):x:\d+:\d+:",  # /etc/passwd line
        r"/etc/passwd",
        r"/etc/shadow",
        # System paths and shells
        r"/bin/(sh|bash|dash|zsh)",
        r"/usr/(?:s?bin|local)/",
        # ls -l / ls -la
        r"^total\s+\d+\s*$",  # ls -l header
        r"^[\-dlcbps][rwxsStT-]{9}\s+\d+\s+\S+\s+\S+\s+\d+",  # ls -l permission line
        # Network info: ifconfig / ip a
        r"\binet\s+(?:addr:)?\d{1,3}(?:\.\d{1,3}){3}",
        r"\bHWaddr\s+(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",
        r"\bether\s+(?:[0-9a-f]{2}:){5}[0-9a-f]{2}",
        # uname / hostnamectl
        r"\bLinux\s+\S+\s+\d+\.\d+",  # uname -a head
        r"\bGNU/Linux\b",
        r"\bDarwin\s+\S+\s+\d+\.\d+",
        # ping output (when the original ping completes alongside an extra
        # command, the response still contains canonical ping framing)
        r"\bbytes from\s+\d{1,3}(?:\.\d{1,3}){3}",
        r"\bicmp_seq=\d+",
        # Shell error noise — exploit succeeded but the appended cmd misfired
        r"\bcommand not found\b",
        r"\bpermission denied\b",
        r"\bno such file or directory\b",
        r"^sh:\s+\d+:",  # bash error prefix
        r"\$\s*$",  # Shell prompt artifact
        # Common service users surfaced by whoami in web contexts
        r"^(?:www-data|apache|nginx|httpd|nobody|tomcat)\s*$",
    ]
]

_WINDOWS_OUTPUT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE | re.MULTILINE)
    for p in [
        r"volume in drive [a-z] (has no label|is)",
        r"volume serial number",
        r"directory of [a-z]:\\",
        r"windows ip configuration",
        r"ipv?[46]?\s*address[\.\s]*:\s*\d{1,3}(?:\.\d{1,3}){3}",
        r"subnet mask[\.\s]*:\s*\d{1,3}(?:\.\d{1,3}){3}",
        r"physical address[\.\s]*:\s*(?:[0-9a-f]{2}-){5}[0-9a-f]{2}",
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
    SUPPORTED_ENCODINGS = ("none", "url", "double_url")

    def __init__(
        self,
        settings: Settings,
        http_client: HTTPClient,
        rate_limiter: GlobalRateLimiter | None = None,
    ) -> None:
        super().__init__(settings, http_client, rate_limiter)

    async def _detect(
        self, vector: AttackVector, payload: str, encoding: str = "none"
    ) -> RawFinding | None:
        """Try one payload; return a finding if CMDi evidence is found."""
        try:
            payload_lower = payload.lower()

            # Time-based payloads (sleep / ping -c N / ping -n N)
            if any(kw in payload_lower for kw in ("sleep ", "ping -c", "ping -n")):
                return await self._detect_time_based(vector, payload, encoding)

            # Error-based / output-based
            return await self._detect_error_based(vector, payload, encoding)

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

    async def _detect_error_based(
        self, vector: AttackVector, payload: str, encoding: str = "none"
    ) -> RawFinding | None:
        response, elapsed = await self._send(vector, payload, encoding=encoding)
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
                    encoding,
                )
        return None

    async def _detect_time_based(
        self, vector: AttackVector, payload: str, encoding: str = "none"
    ) -> RawFinding | None:
        try:
            _, baseline_ms = await self._send_baseline(vector)
        except Exception:
            baseline_ms = 0

        t0 = time.monotonic()
        try:
            response, _ = await self._send(vector, payload, no_retry=True, encoding=encoding)
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
                encoding,
            )
        return None
