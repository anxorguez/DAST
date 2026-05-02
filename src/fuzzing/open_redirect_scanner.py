"""Open Redirect scanner: Location header and meta-refresh detection."""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

import httpx
from loguru import logger

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.core.rate_limiter import GlobalRateLimiter
from src.vectors.models import AttackVector, VulnType

from .base_scanner import BaseScanner, _format_exc

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# HTTP status codes that indicate a redirect response.
_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

# Domains used in our redirect payloads to detect if the server echoes them.
# ``evil.com`` is the historical probe; ``evil.tld`` mirrors the canonical
# OWASP example used in newer payload variants — keeping both lets the
# scanner survive payload list updates without losing detections.
_PROBE_DOMAINS = frozenset({"evil.com", "evil.tld", "attacker.com"})

# Meta-refresh redirect pattern in HTML body.
_META_REFRESH_PATTERN = re.compile(
    r'<meta\s+http-equiv=["\']?refresh["\']?\s+content=["\'][^"\']*url=([^"\'>\s]+)',
    re.IGNORECASE,
)

# JavaScript location assignment patterns.
_JS_REDIRECT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'window\.location\s*=\s*["\']([^"\']+)', re.IGNORECASE),
    re.compile(r'window\.location\.href\s*=\s*["\']([^"\']+)', re.IGNORECASE),
    re.compile(r'window\.location\.replace\(["\']([^"\']+)', re.IGNORECASE),
    re.compile(r'document\.location\s*=\s*["\']([^"\']+)', re.IGNORECASE),
]


def _is_external_url(url: str, probe_domains: frozenset[str]) -> bool:
    """Return True if *url* resolves to one of *probe_domains*.

    Tolerates the common attacker-controlled redirect shapes seen in the
    wild: absolute URLs (``https://evil.tld``), protocol-relative URLs
    (``//evil.tld``), URLs prefixed with whitespace or null bytes that
    some servers don't strip, and URL-encoded slashes (``%2F%2Fevil.tld``).
    """
    if not url:
        return False
    try:
        candidate = url.strip().lstrip("\x00")
        # Decode percent-encoded leading slashes that some apps don't
        # canonicalise before forwarding to ``Location``.
        lowered = candidate.lower()
        if lowered.startswith("%2f%2f"):
            candidate = "//" + candidate[6:]
        # ``urlparse`` can't see the host of a bare ``evil.tld/path`` —
        # prefix a scheme-less ``//`` so the netloc parses correctly.
        if "://" not in candidate and not candidate.startswith("//"):
            candidate = f"//{candidate}"
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        return any(host == d or host.endswith(f".{d}") for d in probe_domains)
    except Exception:
        return False


class OpenRedirectScanner(BaseScanner):
    """Detects open redirects by injecting external URLs into redirect parameters.

    Sends requests with follow_redirects=False so the 3xx response is captured.
    Checks:
    1. Location header pointing to the probe domain (CONFIRMED).
    2. Meta-refresh or JS location redirect to the probe domain (LIKELY).
    """

    VULN_TYPE = VulnType.OPEN_REDIRECT

    def __init__(
        self,
        settings: Settings,
        http_client: HTTPClient,
        rate_limiter: GlobalRateLimiter | None = None,
    ) -> None:
        super().__init__(settings, http_client, rate_limiter)

    async def _detect(self, vector: AttackVector, payload: str) -> RawFinding | None:
        """Inject *payload* and look for redirect to the probe domain."""
        try:
            # We need the raw 3xx response, not the followed redirect.
            response, elapsed = await self._send_no_follow(vector, payload)
            status = response.status_code
            body = response.text

            # Strategy 1: Location header redirects to our probe domain.
            if status in _REDIRECT_STATUS_CODES:
                location = response.headers.get("location", "")
                if location and _is_external_url(location, _PROBE_DOMAINS):
                    evidence = (
                        f"Open Redirect: HTTP {status} Location header '{location}' "
                        f"points to external domain controlled by attacker."
                    )
                    logger.debug(
                        "OpenRedirect confirmed: {url} [{field}] location={loc}",
                        url=vector.target_url,
                        field=vector.field_name,
                        loc=location,
                    )
                    return self._make_finding(
                        vector,
                        payload,
                        response,
                        elapsed,
                        Confidence.CONFIRMED,
                        evidence,
                    )

            # Strategy 2: Meta-refresh redirect in the HTML body.
            meta_match = _META_REFRESH_PATTERN.search(body)
            if meta_match:
                redirect_url = meta_match.group(1)
                if _is_external_url(redirect_url, _PROBE_DOMAINS):
                    evidence = (
                        f"Open Redirect: <meta http-equiv='refresh'> redirects "
                        f"to '{redirect_url}' (HTTP {status})."
                    )
                    return self._make_finding(
                        vector,
                        payload,
                        response,
                        elapsed,
                        Confidence.LIKELY,
                        evidence,
                    )

            # Strategy 3: JavaScript location assignment.
            for js_pat in _JS_REDIRECT_PATTERNS:
                js_match = js_pat.search(body)
                if js_match:
                    js_url = js_match.group(1)
                    if _is_external_url(js_url, _PROBE_DOMAINS):
                        evidence = (
                            f"Open Redirect: JavaScript redirect to '{js_url}' "
                            f"detected in response body (HTTP {status})."
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
                "OpenRedirectScanner error on {url} [{field}]: {err}",
                url=vector.target_url,
                field=vector.field_name,
                err=_format_exc(exc),
            )

        return None

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    async def _send_no_follow(
        self, vector: AttackVector, payload: str
    ) -> tuple[httpx.Response, int]:
        """Send request without following redirects to capture the 3xx response.

        The shared :class:`HTTPClient` is constructed with
        ``follow_redirects=True`` so the fuzz-path scanners see the final
        page; for open-redirect detection that hides the 302 + ``Location``
        header which is exactly the signal we need.  We override the flag
        per-request and update the BaseScanner counters inline so the
        early-abort heuristic doesn't fire on a stream of valid 302s
        (which would otherwise look like "0 valid HTTP responses").
        """
        params = {**vector.extra_params, vector.field_name: payload}

        start = time.monotonic()
        try:
            if vector.method == "POST":
                response = await self._http.post_no_retry(
                    vector.target_url, data=params, follow_redirects=False
                )
            else:
                response = await self._http.get_no_retry(
                    vector.target_url, params=params, follow_redirects=False
                )
        except Exception:
            self._payload_net_error_tally += 1
            raise
        elapsed_ms = int((time.monotonic() - start) * 1000)
        self._payload_response_tally += 1
        return response, elapsed_ms
