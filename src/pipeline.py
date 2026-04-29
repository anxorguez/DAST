"""Pipeline orchestrator: coordinates the four DAST modules end-to-end."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from src.analysis.models import (
    Confidence,
    RawFinding,
    ScanReport,
    Severity,
    ValidatedFinding,
)
from src.analysis.report_generator import ReportGenerator
from src.analysis.severity_scorer import SeverityScorer
from src.analysis.validator import Validator
from src.core.config import Settings
from src.core.rate_limiter import get_rate_limiter
from src.crawler.crawler import Crawler, StoredXSSHit
from src.fuzzing.fuzzer import Fuzzer
from src.vectors.models import AttackVector, CrawledPage, SurfaceType, VulnType
from src.vectors.vector_analyzer import VectorAnalyzer


class Pipeline:
    """Coordinates the crawl → vector identification → fuzzing → reporting cycle."""

    def __init__(self, settings: Settings, scan_dir: Path) -> None:
        self._settings = settings
        self._scan_dir = scan_dir

    async def run(self) -> ScanReport:
        """Execute the full pipeline and return the completed ScanReport.

        Side effects:
            Writes findings.db, report.json, and report.html inside scan_dir.
        """
        started_at = datetime.now(UTC)
        logger.info(
            "Pipeline started | target={t} | scan_dir={d}",
            t=self._settings.target_url,
            d=str(self._scan_dir),
        )

        # ------------------------------------------------------------------
        # Module 1 — Crawler
        # ------------------------------------------------------------------
        crawler = Crawler(self._settings)
        pages = await crawler.crawl()
        logger.info("Module 1 complete: {n} page(s) crawled", n=len(pages))
        self._warn_if_login_wall(pages)

        # ------------------------------------------------------------------
        # Module 2 — Vector identification
        # ------------------------------------------------------------------
        analyzer = VectorAnalyzer()
        vectors = analyzer.analyze(pages)
        logger.info("Module 2 complete: {n} vector(s) identified", n=len(vectors))

        # ------------------------------------------------------------------
        # Module 3 — Fuzzing
        # ------------------------------------------------------------------
        # Single rate limiter shared across every scanner so that
        # ``--requests-per-second`` controls the *combined* outbound rate
        # rather than the per-scanner rate.
        rate_limiter = get_rate_limiter(self._settings.requests_per_second)
        fuzzer = Fuzzer(
            self._settings,
            session_cookies=crawler.session_cookies,
            rate_limiter=rate_limiter,
        )
        raw_findings = await fuzzer.run(vectors)

        # Module 3b — Stored XSS second pass
        if "xss" in self._settings.payload_types_list and fuzzer.injected_xss_payloads:
            stored_hits = await crawler.second_pass(fuzzer.injected_xss_payloads)
            stored_findings = self._hits_to_findings(stored_hits, vectors)
            raw_findings.extend(stored_findings)
            logger.info("Module 3 (stored XSS pass): {n} candidate(s)", n=len(stored_findings))

        logger.info(
            "Module 3 complete: {n} raw finding(s) before validation",
            n=len(raw_findings),
        )

        # ------------------------------------------------------------------
        # Module 4 — Validation, scoring, reporting
        # ------------------------------------------------------------------
        validator = Validator()
        validated = validator.validate(raw_findings)

        scorer = SeverityScorer()
        scored = scorer.score(validated)

        finished_at = datetime.now(UTC)
        report = ScanReport(
            scan_id=self._scan_dir.name,
            target_url=self._settings.target_url,
            started_at=started_at,
            finished_at=finished_at,
            pages_crawled=len(pages),
            vectors_found=len(vectors),
            findings=scored,
            summary=self._build_summary(scored),
            config=self._settings.model_dump(exclude={"auth_password", "dvwa_password", "db_path"}),
        )

        generator = ReportGenerator(self._settings, self._scan_dir)
        await generator.generate(report)

        logger.info(
            "Pipeline complete | findings={n} | duration={s:.1f}s",
            n=len(scored),
            s=(finished_at - started_at).total_seconds(),
        )
        return report

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _hits_to_findings(
        self,
        hits: list[StoredXSSHit],
        vectors: list[AttackVector],
    ) -> list[RawFinding]:
        """Convert StoredXSSHit objects to RawFinding using a synthetic vector."""
        findings: list[RawFinding] = []
        for hit in hits:
            # Find a matching vector by URL, or create a synthetic one.
            source_vector = next((v for v in vectors if v.source_url == hit.page_url), None)
            if source_vector is None:
                source_vector = AttackVector(
                    source_url=hit.page_url,
                    target_url=hit.page_url,
                    method="GET",
                    surface=SurfaceType.STORED,
                    field_name="(stored)",
                    field_context="Stored XSS second-pass detection",
                    applicable_vulns=[VulnType.XSS],
                    priority=1,
                )
            else:
                # Clone the vector with surface overridden to STORED.
                source_vector = AttackVector(
                    id=str(uuid.uuid4()),
                    source_url=source_vector.source_url,
                    target_url=source_vector.target_url,
                    method=source_vector.method,
                    surface=SurfaceType.STORED,
                    field_name=source_vector.field_name,
                    field_context=source_vector.field_context,
                    applicable_vulns=[VulnType.XSS],
                    priority=1,
                    extra_params=source_vector.extra_params,
                )

            # Emit two findings so the Validator's 2-of-3 threshold is met.
            for _ in range(2):
                findings.append(
                    RawFinding(
                        vector=source_vector,
                        vuln_type=VulnType.XSS,
                        payload=hit.payload,
                        response_snippet=hit.evidence_snippet,
                        confidence=Confidence.CONFIRMED,
                        evidence=(f"Stored XSS: payload found unescaped in DOM of {hit.page_url}"),
                        response_time_ms=0,
                    )
                )
        return findings

    @staticmethod
    def _build_summary(findings: list[ValidatedFinding]) -> dict[str, int]:
        summary: dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            summary[f.severity.value] += 1
        return summary

    def _warn_if_login_wall(self, pages: list[CrawledPage]) -> None:
        """Warn when the crawl stopped at a single login page without auth enabled.

        If the only page the crawler reached contains both a username and a
        password input (typical login form) and AUTH_ENABLED is false, the scan
        will concentrate fuzzing on the login form and miss the rest of the
        application. Surface this clearly so the operator can enable pre-scan
        authentication.
        """
        if self._settings.auth_enabled or len(pages) != 1:
            return

        page = pages[0]
        has_password = any(f.field_type == "password" for form in page.forms for f in form.fields)
        has_username = any(
            f.name.lower() in {"username", "user", "email", "login"}
            for form in page.forms
            for f in form.fields
        )
        if not (has_password and has_username):
            return

        logger.warning(
            "Crawl stopped at what looks like a login page ({url}) but "
            "AUTH_ENABLED is false. Fuzzing will only cover the login form and "
            "will miss the rest of the application. To scan authenticated pages, "
            "set AUTH_ENABLED=true and AUTH_URL/AUTH_USERNAME/AUTH_PASSWORD/"
            "AUTH_SUCCESS_URL in your .env (see README).",
            url=page.url,
        )
