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
