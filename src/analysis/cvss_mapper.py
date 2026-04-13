"""Maps DAST RawFinding instances to CVSS 3.1 vectors.

Each vulnerability type is mapped to a CVSSVector based on the most
common attack scenario observed in the wild.  Sub-type (e.g.
error-based vs time-based SQLi, reflected vs stored XSS) is inferred
from the payload and evidence fields.

CVSS score justifications
--------------------------
* SQLi error/UNION (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) → 9.1
  - Network-exploitable, no privileges, full DB read/write.
* SQLi time-based/blind (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N) → 5.9
  - Higher complexity (needs inference loop), limited immediate impact.
* XSS reflected (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) → 6.1
  - Requires victim to click a link; scope changes to victim's browser.
* XSS stored (AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N) → 5.4
  - Needs write access to persist payload (low privileges).
* CMDi (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) → 9.8
  - Complete system compromise.
* SSRF (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) → 5.3
  - Can pivot to internal services; impact varies widely.
* XXE (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N) → 8.2
  - File disclosure; may escalate to SSRF.
* Deserialization (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) → 9.8
  - Typically leads to RCE.
* Path Traversal (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) → 7.5
  - Arbitrary file read; may expose credentials.
* Open Redirect (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N) → 6.1
  - Phishing vector; same base metrics as reflected XSS.
"""

from __future__ import annotations

from src.analysis.cvss import (
    CVSSAttackComplexity,
    CVSSAttackVector,
    CVSSImpact,
    CVSSPrivilegesRequired,
    CVSSScope,
    CVSSUserInteraction,
    CVSSVector,
)
from src.analysis.models import RawFinding
from src.vectors.models import SurfaceType, VulnType

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TIME_BASED_KEYWORDS: tuple[str, ...] = (
    "sleep(",
    "waitfor delay",
    "pg_sleep(",
    "sleep ",
    "ping -c",
    "ping -n",
)

_UNION_KEYWORDS = ("union",)


def _is_time_based(payload: str) -> bool:
    lower = payload.lower()
    return any(kw in lower for kw in _TIME_BASED_KEYWORDS)


def _is_union(payload: str) -> bool:
    lower = payload.lower()
    return any(kw in lower for kw in _UNION_KEYWORDS)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def map_finding_to_cvss(finding: RawFinding) -> CVSSVector:
    """Return a CVSSVector for *finding* based on vuln type and sub-type.

    Args:
        finding: A RawFinding produced by one of the scanner classes.

    Returns:
        A CVSSVector with all Base Metric fields populated.
    """
    vt = finding.vuln_type
    payload = finding.payload

    if vt == VulnType.SQLI:
        return _map_sqli(payload)

    if vt == VulnType.XSS:
        return _map_xss(finding)

    if vt == VulnType.CMDI:
        return _map_cmdi()

    if vt == VulnType.SSRF:
        return _map_ssrf()

    if vt == VulnType.XXE:
        return _map_xxe()

    if vt == VulnType.DESERIALIZATION:
        return _map_deserialization()

    if vt == VulnType.PATH_TRAVERSAL:
        return _map_path_traversal()

    if vt == VulnType.OPEN_REDIRECT:
        return _map_open_redirect()

    # Default / unknown — minimal impact
    return CVSSVector(
        attack_vector=CVSSAttackVector.NETWORK,
        attack_complexity=CVSSAttackComplexity.LOW,
        privileges_required=CVSSPrivilegesRequired.NONE,
        user_interaction=CVSSUserInteraction.NONE,
        scope=CVSSScope.UNCHANGED,
        confidentiality=CVSSImpact.NONE,
        integrity=CVSSImpact.NONE,
        availability=CVSSImpact.NONE,
    )


# ---------------------------------------------------------------------------
# Per-type mappers
# ---------------------------------------------------------------------------


def _map_sqli(payload: str) -> CVSSVector:
    """SQLi: time-based uses AC:H and reduced impact; others use AC:L + C:H/I:H."""
    if _is_time_based(payload):
        # Blind time-based: higher complexity, limited immediate impact.
        return CVSSVector(
            attack_vector=CVSSAttackVector.NETWORK,
            attack_complexity=CVSSAttackComplexity.HIGH,
            privileges_required=CVSSPrivilegesRequired.NONE,
            user_interaction=CVSSUserInteraction.NONE,
            scope=CVSSScope.UNCHANGED,
            confidentiality=CVSSImpact.LOW,
            integrity=CVSSImpact.NONE,
            availability=CVSSImpact.NONE,
        )
    # Error-based or UNION-based: direct data exfiltration.
    return CVSSVector(
        attack_vector=CVSSAttackVector.NETWORK,
        attack_complexity=CVSSAttackComplexity.LOW,
        privileges_required=CVSSPrivilegesRequired.NONE,
        user_interaction=CVSSUserInteraction.NONE,
        scope=CVSSScope.UNCHANGED,
        confidentiality=CVSSImpact.HIGH,
        integrity=CVSSImpact.HIGH,
        availability=CVSSImpact.NONE,
    )


def _map_xss(finding: RawFinding) -> CVSSVector:
    """XSS: stored requires low privileges; reflected requires no privileges."""
    stored = finding.vector.surface == SurfaceType.STORED
    return CVSSVector(
        attack_vector=CVSSAttackVector.NETWORK,
        attack_complexity=CVSSAttackComplexity.LOW,
        privileges_required=(CVSSPrivilegesRequired.LOW if stored else CVSSPrivilegesRequired.NONE),
        user_interaction=CVSSUserInteraction.REQUIRED,
        scope=CVSSScope.CHANGED,
        confidentiality=CVSSImpact.LOW,
        integrity=CVSSImpact.LOW,
        availability=CVSSImpact.NONE,
    )


def _map_cmdi() -> CVSSVector:
    """CMDi: complete system compromise; no privileges required."""
    return CVSSVector(
        attack_vector=CVSSAttackVector.NETWORK,
        attack_complexity=CVSSAttackComplexity.LOW,
        privileges_required=CVSSPrivilegesRequired.NONE,
        user_interaction=CVSSUserInteraction.NONE,
        scope=CVSSScope.UNCHANGED,
        confidentiality=CVSSImpact.HIGH,
        integrity=CVSSImpact.HIGH,
        availability=CVSSImpact.HIGH,
    )


def _map_ssrf() -> CVSSVector:
    """SSRF: network-accessible, pivots to internal services."""
    return CVSSVector(
        attack_vector=CVSSAttackVector.NETWORK,
        attack_complexity=CVSSAttackComplexity.LOW,
        privileges_required=CVSSPrivilegesRequired.NONE,
        user_interaction=CVSSUserInteraction.NONE,
        scope=CVSSScope.UNCHANGED,
        confidentiality=CVSSImpact.LOW,
        integrity=CVSSImpact.NONE,
        availability=CVSSImpact.NONE,
    )


def _map_xxe() -> CVSSVector:
    """XXE: arbitrary file read; potentially escalates to SSRF."""
    return CVSSVector(
        attack_vector=CVSSAttackVector.NETWORK,
        attack_complexity=CVSSAttackComplexity.LOW,
        privileges_required=CVSSPrivilegesRequired.NONE,
        user_interaction=CVSSUserInteraction.NONE,
        scope=CVSSScope.UNCHANGED,
        confidentiality=CVSSImpact.HIGH,
        integrity=CVSSImpact.LOW,
        availability=CVSSImpact.NONE,
    )


def _map_deserialization() -> CVSSVector:
    """Deserialization: typically leads to RCE; full impact."""
    return CVSSVector(
        attack_vector=CVSSAttackVector.NETWORK,
        attack_complexity=CVSSAttackComplexity.LOW,
        privileges_required=CVSSPrivilegesRequired.NONE,
        user_interaction=CVSSUserInteraction.NONE,
        scope=CVSSScope.UNCHANGED,
        confidentiality=CVSSImpact.HIGH,
        integrity=CVSSImpact.HIGH,
        availability=CVSSImpact.HIGH,
    )


def _map_path_traversal() -> CVSSVector:
    """Path Traversal: arbitrary file read from server filesystem."""
    return CVSSVector(
        attack_vector=CVSSAttackVector.NETWORK,
        attack_complexity=CVSSAttackComplexity.LOW,
        privileges_required=CVSSPrivilegesRequired.NONE,
        user_interaction=CVSSUserInteraction.NONE,
        scope=CVSSScope.UNCHANGED,
        confidentiality=CVSSImpact.HIGH,
        integrity=CVSSImpact.NONE,
        availability=CVSSImpact.NONE,
    )


def _map_open_redirect() -> CVSSVector:
    """Open Redirect: phishing vector; user interaction required."""
    return CVSSVector(
        attack_vector=CVSSAttackVector.NETWORK,
        attack_complexity=CVSSAttackComplexity.LOW,
        privileges_required=CVSSPrivilegesRequired.NONE,
        user_interaction=CVSSUserInteraction.REQUIRED,
        scope=CVSSScope.CHANGED,
        confidentiality=CVSSImpact.LOW,
        integrity=CVSSImpact.LOW,
        availability=CVSSImpact.NONE,
    )
