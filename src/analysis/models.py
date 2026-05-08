"""Data models produced by the Analysis module."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from src.vectors.models import AttackVector, VulnType

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Confidence(StrEnum):
    """How confident the scanner is that this is a real finding."""

    CONFIRMED = "confirmed"  # Direct evidence (exec, SQL error visible)
    LIKELY = "likely"  # Strong indicators but not direct execution
    POSSIBLE = "possible"  # Anomalous response — may be false positive


class Severity(StrEnum):
    """CVSS-inspired severity classification (simplified fixed rules)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Ordering used for sorting (higher index = more severe)
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Fuzzing output
# ---------------------------------------------------------------------------


@dataclass
class RawFinding:
    """A single candidate finding returned by a scanner for one attempt."""

    vector: AttackVector
    vuln_type: VulnType
    payload: str
    response_snippet: str  # Relevant fragment of the HTTP response (max 500 chars)
    confidence: Confidence
    evidence: str  # Human-readable explanation of why this is suspicious
    response_time_ms: int = 0  # Milliseconds; key for time-based detections
    encoding: str = "none"  # Obfuscation applied to the payload, if any
    found_at: datetime = field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Analysis output
# ---------------------------------------------------------------------------


@dataclass
class ValidatedFinding:
    """A confirmed finding after validation, deduplication, and scoring."""

    raw: RawFinding
    severity: Severity = Severity.INFO
    cvss_score: float = 0.0
    cvss_vector_string: str = ""
    remediation: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class ScanHealth:
    """Aggregate diagnostics about how the scan ran (not what it found).

    Distinguishes a quiet scan that genuinely found nothing from a scan that
    self-destructed mid-flight (saturated network, dead target, repeated
    timeouts).  Surfaced in ``report.json`` as ``summary.scanner_health`` so
    a 0-finding report can no longer be silently misread as "no vulns".
    """

    vectors_total: int = 0
    vector_timeouts: int = 0
    early_aborts: int = 0
    scanners_with_zero_valid_responses: int = 0

    @property
    def completion_rate_pct(self) -> float:
        """Fraction of vector × scanner pairs that finished without abort/timeout."""
        if self.vectors_total <= 0:
            return 100.0
        bad = self.vector_timeouts + self.early_aborts
        good = max(0, self.vectors_total - bad)
        return round(100.0 * good / self.vectors_total, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vectors_total": self.vectors_total,
            "vector_timeouts": self.vector_timeouts,
            "early_aborts": self.early_aborts,
            "scanners_with_zero_valid_responses": self.scanners_with_zero_valid_responses,
            "completion_rate_pct": self.completion_rate_pct,
        }


@dataclass
class CrawlStats:
    """Why the BFS crawl stopped, distinguishing exhaustion from truncation.

    ``pages_crawled`` alone cannot tell the analyst whether raising
    ``--max-pages`` would help or whether the target's surface is fully
    discovered — this struct closes that gap.
    """

    crawl_limit_reason: str = "frontier_exhausted"
    queued_unvisited: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "crawl_limit_reason": self.crawl_limit_reason,
            "queued_unvisited": self.queued_unvisited,
        }


@dataclass
class ScanReport:
    """The complete output of a finished scan pipeline execution."""

    scan_id: str
    target_url: str
    started_at: datetime
    finished_at: datetime
    pages_crawled: int
    vectors_found: int
    findings: list[ValidatedFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    # Effective Settings dump (sensitive fields excluded) so the analyst can
    # audit exactly which configuration produced this scan.
    config: dict[str, Any] = field(default_factory=dict)
    # Exact CLI invocation that produced this scan, included so the analyst
    # can reproduce the run from the report alone.
    cli_command: str = ""
    # Run-quality counters: timeouts/aborts/completion rate.  See ScanHealth.
    scanner_health: ScanHealth = field(default_factory=ScanHealth)
    # Why the crawler stopped — see CrawlStats.
    crawl_stats: CrawlStats = field(default_factory=CrawlStats)
