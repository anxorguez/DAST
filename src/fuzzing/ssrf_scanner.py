"""SSRF (Server-Side Request Forgery) scanner: in-band detection."""

from __future__ import annotations

import re

from loguru import logger

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.vectors.models import AttackVector, VulnType

from .base_scanner import BaseScanner, _format_exc

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

# Content patterns that only appear if the server actually fetched an internal resource.
_INTERNAL_CONTENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # AWS IMDSv1 metadata keys
        r"\bami-id\b",
        r"\binstance-id\b",
        r"\bsecurity-credentials\b",
        r"\biam/info\b",
        r"\bplacement/availability-zone\b",
        r"\bpublic-hostname\b",
        # /etc/passwd
        r"root:x:\d+:\d+:",
        r"daemon:x:\d+:",
        r"nobody:x:\d+:",
        # /etc/hosts typical lines
        r"127\.0\.0\.1\s+localhost",
        # Typical internal admin pages
        r"<title>.*admin.*</title>",
        r"phpinfo\(\)",
        r"PHP Version",
        r"Server:\s*Apache",
        r"Server:\s*nginx",
        # Internal service banners
        r"REDIS\s+\d+\.\d+",
        r"MongoDB\s+\d+\.\d+",
        # GCP metadata
        r"\bcomputeMetadata\b",
        r"\bproject-id\b",
    ]
]

# Minimum byte-size difference to consider a response "significantly different".
_SIZE_DIFF_THRESHOLD = 200


class SSRFScanner(BaseScanner):
    """Detects SSRF via in-band response analysis.

    Injects internal/cloud-metadata URLs and checks whether the server
    fetched the resource (CONFIRMED) or returned a notably different
    response body (LIKELY).
    """

    VULN_TYPE = VulnType.SSRF

    def __init__(self, settings: Settings, http_client: HTTPClient) -> None:
        super().__init__(settings, http_client)

    async def _detect(self, vector: AttackVector, payload: str) -> RawFinding | None:
        """Inject *payload* URL and analyse the response for internal content."""
        try:
            # Baseline for size-difference comparison.
            try:
                baseline_resp, _ = await self._send_baseline(vector)
                baseline_size = len(baseline_resp.text)
            except Exception:
                baseline_size = 0

            response, elapsed = await self._send(vector, payload)
            body = response.text

            # Strategy 1: response contains content from an internal resource.
            for pattern in _INTERNAL_CONTENT_PATTERNS:
                match = pattern.search(body)
                if match:
                    evidence = (
                        f"SSRF: internal content pattern '{match.group(0)}' "
                        f"found in response (HTTP {response.status_code}). "
                        f"Payload: {payload}"
                    )
                    logger.debug(
                        "SSRF confirmed: {url} [{field}] -> {ev}",
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

            # Strategy 2: significant size difference suggests the server
            # attempted to fetch the URL (body is different from baseline).
            size_diff = abs(len(body) - baseline_size)
            if size_diff >= _SIZE_DIFF_THRESHOLD and len(body) > 0:
                evidence = (
                    f"SSRF: response size differs from baseline by {size_diff} bytes "
                    f"with SSRF payload (HTTP {response.status_code}). "
                    f"Possible server-side fetch of: {payload}"
                )
                logger.debug(
                    "SSRF likely: {url} [{field}] size_diff={d}",
                    url=vector.target_url,
                    field=vector.field_name,
                    d=size_diff,
                )
                return self._make_finding(
                    vector,
                    payload,
                    response,
                    elapsed,
                    Confidence.LIKELY,
                    evidence,
                )

        except Exception as exc:
            logger.debug(
                "SSRFScanner error on {url} [{field}]: {err}",
                url=vector.target_url,
                field=vector.field_name,
                err=_format_exc(exc),
            )

        return None
