"""Assigns CVSS 3.1 severity and remediation advice to validated findings.

Severity is derived from the calculated CVSS 3.1 Base Score using the
standard numeric bands:
  9.0–10.0 → CRITICAL
  7.0–8.9  → HIGH
  4.0–6.9  → MEDIUM
  0.1–3.9  → LOW
  0.0      → INFO
"""

from __future__ import annotations

from src.analysis.cvss import calculate_base_score, vector_to_string
from src.analysis.cvss_mapper import map_finding_to_cvss
from src.analysis.models import RawFinding, Severity, ValidatedFinding
from src.vectors.models import VulnType

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
    VulnType.SSRF: (
        "Validate and sanitise all user-supplied URLs before the server makes "
        "outbound requests. Use an allowlist of permitted domains/IPs. Block "
        "access to cloud metadata endpoints (169.254.169.254) and private IP "
        "ranges (10.x, 172.16-31.x, 192.168.x). Disable HTTP redirects in "
        "server-side HTTP clients."
    ),
    VulnType.XXE: (
        "Disable XML external entity processing in all XML parsers. Set "
        "FEATURE_EXTERNAL_GENERAL_ENTITIES and FEATURE_EXTERNAL_PARAMETER_ENTITIES "
        "to false. Use safer data formats (JSON) where possible. Apply input "
        "validation to reject DOCTYPE declarations."
    ),
    VulnType.DESERIALIZATION: (
        "Avoid deserialising data from untrusted sources. Use integrity checks "
        "(HMAC) before deserialisation. Prefer safe data formats (JSON/XML with "
        "schema validation) over native serialisation. Run deserialisation in "
        "sandboxed contexts with minimal permissions."
    ),
    VulnType.PATH_TRAVERSAL: (
        "Validate all file path inputs against an allowlist of permitted paths. "
        "Use a canonical path check (realpath/Path.resolve) and reject paths "
        "outside the intended base directory. Never construct file paths by "
        "concatenating user input."
    ),
    VulnType.OPEN_REDIRECT: (
        "Validate redirect destinations against an allowlist of permitted URLs "
        "or domains. Avoid passing user-supplied URLs directly to redirect "
        "responses. If redirection is required, use an indirect reference map "
        "with opaque tokens instead of raw URLs."
    ),
}


def _severity_from_score(score: float) -> Severity:
    """Map a CVSS 3.1 base score to a Severity enum value."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


class SeverityScorer:
    """Assigns Severity, CVSS 3.1 score, vector string, and remediation text."""

    def score(self, findings: list[ValidatedFinding]) -> list[ValidatedFinding]:
        """Mutate *findings* in-place by filling severity, cvss_score,
        cvss_vector_string, and remediation.

        Returns the same list for chaining convenience.
        """
        for finding in findings:
            cvss_vec = map_finding_to_cvss(finding.raw)
            base_score = calculate_base_score(cvss_vec)
            finding.cvss_score = base_score
            finding.cvss_vector_string = vector_to_string(cvss_vec)
            finding.severity = _severity_from_score(base_score)
            finding.remediation = _REMEDIATION.get(finding.raw.vuln_type, "")
        return findings
