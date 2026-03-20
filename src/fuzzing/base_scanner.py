"""Abstract base class shared by all vulnerability scanners."""

from __future__ import annotations

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


class BaseScanner(ABC):
    """Abstract base for SQLi, XSS, and CMDi scanners.

    Subclasses implement ``_detect`` which is called up to RETRY_COUNT
    times per payload. The scanner only emits a finding when at least
    CONFIRM_THRESHOLD attempts succeed.
    """

    VULN_TYPE: VulnType  # Must be set by every concrete subclass.

    def __init__(self, settings: Settings, http_client: HTTPClient) -> None:
        self._settings = settings
        self._http = http_client

    # -------------------------------------------------------------------
    # Public interface
    # -------------------------------------------------------------------

    async def scan(
        self, vector: AttackVector, payloads: list[str]
    ) -> list[RawFinding]:
        """Scan *vector* with *payloads* and return confirmed findings.

        For each payload, ``_detect`` is called RETRY_COUNT times. A
        RawFinding is emitted only when at least CONFIRM_THRESHOLD of those
        attempts return a Confidence value other than POSSIBLE.
        """
        findings: list[RawFinding] = []

        for payload in payloads:
            confirmed_hits: list[RawFinding] = []

            for _ in range(RETRY_COUNT):
                hit = await self._detect(vector, payload)
                if hit is not None:
                    confirmed_hits.append(hit)

            if len(confirmed_hits) >= CONFIRM_THRESHOLD:
                # Emit all confirmed hits so the Validator can group them and
                # apply its own confirmation threshold (2-of-N rule).
                findings.extend(confirmed_hits)

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
