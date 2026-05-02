"""Fuzzing orchestrator: iterates over vectors and dispatches to scanners."""

from __future__ import annotations

import asyncio
from typing import Any

from loguru import logger

from src.analysis.models import RawFinding, ScanHealth
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.core.rate_limiter import GlobalRateLimiter
from src.vectors.models import AttackVector, VulnType

from .base_scanner import BaseScanner
from .cmdi_scanner import CMDiScanner
from .deserialization_scanner import DeserializationScanner
from .open_redirect_scanner import OpenRedirectScanner
from .path_traversal_scanner import PathTraversalScanner
from .payload_loader import PayloadLoader
from .sqli_scanner import SQLiScanner
from .ssrf_scanner import SSRFScanner
from .xss_scanner import XSSScanner
from .xxe_scanner import XXEScanner

_SCANNER_MAP: dict[VulnType, type[BaseScanner]] = {
    VulnType.SQLI: SQLiScanner,
    VulnType.XSS: XSSScanner,
    VulnType.CMDI: CMDiScanner,
    VulnType.SSRF: SSRFScanner,
    VulnType.XXE: XXEScanner,
    VulnType.DESERIALIZATION: DeserializationScanner,
    VulnType.PATH_TRAVERSAL: PathTraversalScanner,
    VulnType.OPEN_REDIRECT: OpenRedirectScanner,
}


class Fuzzer:
    """Drives the injection testing pipeline.

    Vectors are processed concurrently, bounded by *concurrent_vectors*
    from Settings.  Each scanner further parallelises payload testing
    (see BaseScanner.scan()).  Tracks all XSS payloads that were actually
    sent so the pipeline can perform a stored XSS second pass.
    """

    def __init__(
        self,
        settings: Settings,
        session_cookies: list[dict[str, Any]] | None = None,
        rate_limiter: GlobalRateLimiter | None = None,
    ) -> None:
        self._settings = settings
        self._loader = PayloadLoader()
        self._session_cookies = session_cookies or []
        self._rate_limiter = rate_limiter
        # Public attribute: XSS payloads injected into the target during fuzzing.
        self.injected_xss_payloads: list[str] = []
        self._xss_lock = asyncio.Lock()
        # Run-quality counters surfaced as ``summary.scanner_health`` in the
        # final report.  The fuzzer counts a (vector × scanner) pair once
        # for each outcome — a clean run, a per-vector timeout, an
        # early-abort because every payload returned a network error.
        self.health: ScanHealth = ScanHealth()
        self._health_lock = asyncio.Lock()

    async def run(self, vectors: list[AttackVector]) -> list[RawFinding]:
        """Fuzz all *vectors* concurrently and return confirmed raw findings.

        Args:
            vectors: Attack vectors produced by VectorAnalyzer.

        Returns:
            All confirmed RawFinding instances across all scanners and vectors.
        """
        max_concurrent = max(1, self._settings.concurrent_vectors)
        vector_sem = asyncio.Semaphore(max_concurrent)

        async with HTTPClient(
            timeout=self._settings.request_timeout,
            max_retries=self._settings.scanner_http_retries,
            session_cookies=self._session_cookies,
        ) as http_client:
            tasks = [
                asyncio.create_task(self._fuzz_vector(vector_sem, vector, http_client))
                for vector in vectors
            ]
            batches = await asyncio.gather(*tasks)

        all_findings = [f for batch in batches for f in batch]

        logger.info(
            "Fuzzing complete: {n} confirmed finding(s) across {v} vector(s)",
            n=len(all_findings),
            v=len(vectors),
        )
        return all_findings

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    async def _fuzz_vector(
        self,
        sem: asyncio.Semaphore,
        vector: AttackVector,
        http_client: HTTPClient,
    ) -> list[RawFinding]:
        """Fuzz one *vector* for all applicable vulnerability types."""
        async with sem:
            findings: list[RawFinding] = []
            enabled_types = set(self._settings.payload_types_list)
            max_payloads = self._settings.max_payloads_per_vector

            for vuln_type in vector.applicable_vulns:
                if vuln_type.value not in enabled_types:
                    continue

                payloads = self._loader.load(vuln_type, max_payloads)
                if not payloads:
                    logger.warning("No payloads found for {vt}", vt=vuln_type.value)
                    continue

                scanner = _SCANNER_MAP[vuln_type](self._settings, http_client, self._rate_limiter)
                # Hard wall-clock cap per (vector × scanner).  If a single
                # endpoint stalls (slow target, tarpit, broken vhost), we
                # cancel the scanner and move on — the early-abort heuristic
                # in BaseScanner handles the common case but doesn't help if
                # individual requests hang for tens of seconds each.
                timeout_s = max(1, self._settings.scanner_vector_timeout_seconds)
                vector_timed_out = False
                try:
                    vt_findings = await asyncio.wait_for(
                        scanner.scan(vector, payloads),
                        timeout=timeout_s,
                    )
                except TimeoutError:
                    vector_timed_out = True
                    # ``wait_for`` cancelled scan() mid-flight.  Recover
                    # whatever the scanner had already confirmed before the
                    # cancel — without this the late time-based payloads
                    # could burn the entire budget and discard real
                    # error-based hits collected earlier in the same scan.
                    vt_findings = list(scanner.partial_findings)
                    logger.warning(
                        "Scanner {vt} timed out after {t}s on {url} [{field}]; "
                        "skipping remaining payloads for this scanner "
                        "(kept {kept} partial finding(s))",
                        vt=vuln_type.value,
                        t=timeout_s,
                        url=vector.target_url,
                        field=vector.field_name,
                        kept=len(vt_findings),
                    )
                findings.extend(vt_findings)

                # Health bookkeeping: count this (vector × scanner) attempt
                # exactly once for the appropriate bucket so the analyst
                # can read `summary.scanner_health` in the report and tell
                # a quiet scan from a degraded one.
                async with self._health_lock:
                    self.health.vectors_total += 1
                    if vector_timed_out:
                        self.health.vector_timeouts += 1
                    elif scanner.aborted_early:
                        self.health.early_aborts += 1
                        self.health.scanners_with_zero_valid_responses += 1

                if vt_findings:
                    logger.info(
                        "Scanner {vt}: {n} finding(s) on {url} [{field}]",
                        vt=vuln_type.value,
                        n=len(vt_findings),
                        url=vector.target_url,
                        field=vector.field_name,
                    )

                # Track XSS payloads for the stored XSS second pass.
                if vuln_type == VulnType.XSS:
                    async with self._xss_lock:
                        for p in payloads:
                            if p not in self.injected_xss_payloads:
                                self.injected_xss_payloads.append(p)

            return findings
