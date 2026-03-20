"""Fuzzing orchestrator: iterates over vectors and dispatches to scanners."""

from __future__ import annotations

from loguru import logger

from src.analysis.models import RawFinding
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.vectors.models import AttackVector, VulnType

from .base_scanner import BaseScanner
from .cmdi_scanner import CMDiScanner
from .payload_loader import PayloadLoader
from .sqli_scanner import SQLiScanner
from .xss_scanner import XSSScanner

_SCANNER_MAP: dict[VulnType, type[BaseScanner]] = {
    VulnType.SQLI: SQLiScanner,
    VulnType.XSS: XSSScanner,
    VulnType.CMDI: CMDiScanner,
}


class Fuzzer:
    """Drives the injection testing pipeline.

    Iterates sequentially over every (vector x vuln_type) combination and
    dispatches to the appropriate scanner. Tracks all XSS payloads that
    were actually sent so the pipeline can perform a stored XSS second pass.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._loader = PayloadLoader()
        # Public attribute: XSS payloads injected into the target during fuzzing.
        self.injected_xss_payloads: list[str] = []

    async def run(self, vectors: list[AttackVector]) -> list[RawFinding]:
        """Fuzz all *vectors* and return the list of confirmed raw findings.

        Args:
            vectors: Attack vectors produced by VectorAnalyzer.

        Returns:
            All confirmed RawFinding instances across all scanners and vectors.
        """
        all_findings: list[RawFinding] = []
        enabled_types = set(self._settings.payload_types_list)
        max_payloads = self._settings.max_payloads_per_vector

        async with HTTPClient(timeout=self._settings.request_timeout) as http_client:
            for vector in vectors:
                for vuln_type in vector.applicable_vulns:
                    if vuln_type.value not in enabled_types:
                        continue

                    payloads = self._loader.load(vuln_type, max_payloads)
                    if not payloads:
                        logger.warning(
                            "No payloads found for {vt}", vt=vuln_type.value
                        )
                        continue

                    scanner = _SCANNER_MAP[vuln_type](self._settings, http_client)
                    findings = await scanner.scan(vector, payloads)
                    all_findings.extend(findings)

                    if findings:
                        logger.info(
                            "Scanner {vt}: {n} finding(s) on {url} [{field}]",
                            vt=vuln_type.value,
                            n=len(findings),
                            url=vector.target_url,
                            field=vector.field_name,
                        )

                    # Track XSS payloads for the stored XSS second pass.
                    if vuln_type == VulnType.XSS:
                        for p in payloads:
                            if p not in self.injected_xss_payloads:
                                self.injected_xss_payloads.append(p)

        logger.info(
            "Fuzzing complete: {n} confirmed finding(s) across {v} vector(s)",
            n=len(all_findings),
            v=len(vectors),
        )
        return all_findings
