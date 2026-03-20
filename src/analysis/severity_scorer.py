"""Assigns CVSS-inspired severity and remediation advice to validated findings.

Severity rules are fixed (not heuristic) as defined in the design decisions:

  - SQLi error-based or UNION-based  -> CRITICAL  (9.0)
  - SQLi blind (boolean or time)     -> HIGH       (7.5)
  - XSS stored                       -> HIGH       (7.0)
  - XSS reflected or DOM-based       -> MEDIUM     (5.0)
  - CMDi error-based                 -> CRITICAL   (9.5)
  - CMDi time-based                  -> HIGH       (7.5)
  - Any other finding                -> INFO       (0.0)
"""

from __future__ import annotations

from src.analysis.models import RawFinding, Severity, ValidatedFinding
from src.vectors.models import SurfaceType, VulnType

# ---------------------------------------------------------------------------
# Remediation advice strings (fixed per vulnerability type)
# ---------------------------------------------------------------------------

_REMEDIATION: dict[VulnType, str] = {
    VulnType.SQLI: (
        "Use parameterised queries (prepared statements) for all database interactions. "
        "Never concatenate user input into SQL strings. Apply the principle of least "
        "privilege to database accounts."
    ),
    VulnType.XSS: (
        "Escape all user-supplied data before rendering it in HTML contexts. "
        "Use a Content Security Policy (CSP) header. Avoid innerHTML and "
        "document.write(); prefer textContent or DOM APIs."
    ),
    VulnType.CMDI: (
        "Never pass user input directly to OS command execution functions. "
        "Use library APIs instead of shell commands. If shell execution is "
        "unavoidable, whitelist allowed characters and use parameterised "
        "shell argument construction."
    ),
}


class SeverityScorer:
    """Assigns Severity, a CVSS-simplified score, and remediation text."""

    def score(self, findings: list[ValidatedFinding]) -> list[ValidatedFinding]:
        """Mutate *findings* in-place by filling severity, cvss_score, and remediation.

        Returns the same list for chaining convenience.
        """
        for finding in findings:
            finding.severity, finding.cvss_score = self._classify(finding.raw)
            finding.remediation = _REMEDIATION.get(finding.raw.vuln_type, "")
        return findings

    # -------------------------------------------------------------------
    # Classification logic
    # -------------------------------------------------------------------

    def _classify(self, raw: RawFinding) -> tuple[Severity, float]:
        vt = raw.vuln_type
        payload_lower = raw.payload.lower()

        if vt == VulnType.SQLI:
            return self._classify_sqli(payload_lower)

        if vt == VulnType.XSS:
            return self._classify_xss(raw)

        if vt == VulnType.CMDI:
            return self._classify_cmdi(payload_lower)

        return Severity.INFO, 0.0

    def _classify_sqli(self, payload_lower: str) -> tuple[Severity, float]:
        # Time-based or boolean-based payloads -> HIGH
        if any(
            kw in payload_lower
            for kw in ("sleep(", "waitfor delay", "pg_sleep(", "and 1=1", "and 1=2")
        ):
            return Severity.HIGH, 7.5
        # UNION-based or anything that provoked an error -> CRITICAL
        return Severity.CRITICAL, 9.0

    def _classify_xss(self, raw: RawFinding) -> tuple[Severity, float]:
        # Stored XSS is identified by the surface type set during second-pass.
        if raw.vector.surface == SurfaceType.STORED:
            return Severity.HIGH, 7.0
        # Reflected and DOM-based.
        return Severity.MEDIUM, 5.0

    def _classify_cmdi(self, payload_lower: str) -> tuple[Severity, float]:
        # Time-based payloads -> HIGH
        if any(
            kw in payload_lower for kw in ("sleep ", "ping -c", "ping -n")
        ):
            return Severity.HIGH, 7.5
        # Error/output-based -> CRITICAL
        return Severity.CRITICAL, 9.5
