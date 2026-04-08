"""Abstract base class shared by all vulnerability scanners."""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod

import httpx

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.vectors.models import AttackVector, VulnType

# Number of times each payload is retried to confirm a finding.
RETRY_COUNT = 3
# Minimum number of successful detections out of RETRY_COUNT to confirm.
CONFIRM_THRESHOLD = 2

# Keywords that identify time-based payloads.  These must run sequentially
# because parallel execution corrupts timing measurements.
_TIME_BASED_KEYWORDS: tuple[str, ...] = (
    "sleep(",
    "waitfor delay",
    "pg_sleep(",
    "sleep ",
    "ping -c",
    "ping -n",
)


def _is_time_based(payload: str) -> bool:
    """Return True if *payload* uses a time-based delay technique."""
    lower = payload.lower()
    return any(kw in lower for kw in _TIME_BASED_KEYWORDS)


class BaseScanner(ABC):
    """Abstract base for all vulnerability scanners.

    Subclasses implement ``_detect`` which is called up to RETRY_COUNT
    times per payload. The scanner only emits a finding when at least
    CONFIRM_THRESHOLD attempts succeed.

    Concurrency model
    -----------------
    * Different payloads are tested concurrently, bounded by
      *concurrent_payloads* from Settings.
    * Time-based payloads run sequentially behind a dedicated lock to
      avoid corrupting timing measurements.
    * The retry loop (RETRY_COUNT attempts) within a single payload is
      always sequential.
    """

    VULN_TYPE: VulnType  # Must be set by every concrete subclass.

    def __init__(self, settings: Settings, http_client: HTTPClient) -> None:
        self._settings = settings
        self._http = http_client
        # Lock ensures time-based payloads don't run concurrently.
        self._time_based_lock: asyncio.Lock = asyncio.Lock()

    # -------------------------------------------------------------------
    # Public interface
    # -------------------------------------------------------------------

    async def scan(
        self,
        vector: AttackVector,
        payloads: list[str],
        semaphore: asyncio.Semaphore | None = None,
    ) -> list[RawFinding]:
        """Scan *vector* with *payloads* and return confirmed findings.

        Concurrent payloads are bounded by *concurrent_payloads* from
        Settings (or the optional external *semaphore*).  Time-based
        payloads bypass the pool and run behind a dedicated serial lock.

        Args:
            vector: The injection target.
            payloads: Payload strings to test.
            semaphore: Optional external semaphore (unused, kept for API
                compatibility with the Fuzzer's vector-level semaphore).

        Returns:
            All confirmed RawFinding instances for this vector.
        """
        max_concurrent = max(1, self._settings.concurrent_payloads)
        payload_sem = asyncio.Semaphore(max_concurrent)

        findings: list[RawFinding] = []
        findings_lock = asyncio.Lock()

        rps = self._settings.requests_per_second

        async def _scan_one(payload: str) -> None:
            if _is_time_based(payload):
                # Time-based payloads run serially to preserve timing accuracy.
                async with self._time_based_lock:
                    hits = await self._retry_detect(vector, payload)
            else:
                async with payload_sem:
                    if rps > 0:
                        await asyncio.sleep(1.0 / rps)
                    hits = await self._retry_detect(vector, payload)

            if hits:
                async with findings_lock:
                    findings.extend(hits)

        tasks = [asyncio.create_task(_scan_one(p)) for p in payloads]
        await asyncio.gather(*tasks)
        return findings

    # -------------------------------------------------------------------
    # Abstract method for subclasses
    # -------------------------------------------------------------------

    @abstractmethod
    async def _detect(
        self, vector: AttackVector, payload: str
    ) -> RawFinding | None:
        """Attempt to detect a vulnerability for one payload against one vector.

        Returns:
            A RawFinding if evidence is found, otherwise None.
        """
        ...

    # -------------------------------------------------------------------
    # Shared helpers
    # -------------------------------------------------------------------

    async def _retry_detect(
        self, vector: AttackVector, payload: str
    ) -> list[RawFinding]:
        """Run _detect up to RETRY_COUNT times and return hits if ≥ CONFIRM_THRESHOLD."""
        confirmed_hits: list[RawFinding] = []
        for _ in range(RETRY_COUNT):
            hit = await self._detect(vector, payload)
            if hit is not None:
                confirmed_hits.append(hit)
        if len(confirmed_hits) >= CONFIRM_THRESHOLD:
            return confirmed_hits
        return []

    async def _send(
        self,
        vector: AttackVector,
        payload: str,
        no_retry: bool = False,
    ) -> tuple[httpx.Response, int]:
        """Send an HTTP request with *payload* injected into *vector*.

        Returns:
            Tuple of (response, elapsed_milliseconds).
        """
        params = {**vector.extra_params, vector.field_name: payload}

        start = time.monotonic()
        if vector.method == "POST":
            if no_retry:
                response = await self._http.post_no_retry(
                    vector.target_url, data=params
                )
            else:
                response = await self._http.post(vector.target_url, data=params)
        else:
            if no_retry:
                response = await self._http.get_no_retry(
                    vector.target_url, params=params
                )
            else:
                response = await self._http.get(vector.target_url, params=params)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return response, elapsed_ms

    async def _send_baseline(
        self, vector: AttackVector
    ) -> tuple[httpx.Response, int]:
        """Send a benign baseline request for comparison."""
        return await self._send(vector, "DAST_BASELINE_1337")

    @staticmethod
    def _truncate(text: str, max_len: int = 500) -> str:
        if len(text) <= max_len:
            return text
        return text[:max_len] + "..."

    def _make_finding(
        self,
        vector: AttackVector,
        payload: str,
        response: httpx.Response,
        elapsed_ms: int,
        confidence: Confidence,
        evidence: str,
    ) -> RawFinding:
        snippet = self._truncate(response.text)
        return RawFinding(
            vector=vector,
            vuln_type=self.VULN_TYPE,
            payload=payload,
            response_snippet=snippet,
            confidence=confidence,
            evidence=evidence,
            response_time_ms=elapsed_ms,
        )
