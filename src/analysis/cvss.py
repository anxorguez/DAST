"""CVSS 3.1 Base Score calculation.

Implements the exact CVSS v3.1 Base Score formula as defined in:
https://www.first.org/cvss/v3.1/specification-document

Enums and numeric constants match the CVSS 3.1 specification tables.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum


# ---------------------------------------------------------------------------
# CVSS 3.1 Metric Enumerations
# ---------------------------------------------------------------------------


class CVSSAttackVector(str, Enum):
    """Attack Vector (AV) metric."""

    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class CVSSAttackComplexity(str, Enum):
    """Attack Complexity (AC) metric."""

    LOW = "L"
    HIGH = "H"


class CVSSPrivilegesRequired(str, Enum):
    """Privileges Required (PR) metric."""

    NONE = "N"
    LOW = "L"
    HIGH = "H"


class CVSSUserInteraction(str, Enum):
    """User Interaction (UI) metric."""

    NONE = "N"
    REQUIRED = "R"


class CVSSScope(str, Enum):
    """Scope (S) metric."""

    UNCHANGED = "U"
    CHANGED = "C"


class CVSSImpact(str, Enum):
    """Confidentiality / Integrity / Availability Impact metrics."""

    NONE = "N"
    LOW = "L"
    HIGH = "H"


# ---------------------------------------------------------------------------
# Numeric constants from CVSS 3.1 specification
# ---------------------------------------------------------------------------

_AV_SCORES: dict[CVSSAttackVector, float] = {
    CVSSAttackVector.NETWORK: 0.85,
    CVSSAttackVector.ADJACENT: 0.62,
    CVSSAttackVector.LOCAL: 0.55,
    CVSSAttackVector.PHYSICAL: 0.20,
}

_AC_SCORES: dict[CVSSAttackComplexity, float] = {
    CVSSAttackComplexity.LOW: 0.77,
    CVSSAttackComplexity.HIGH: 0.44,
}

# PR scores vary depending on whether Scope is Changed.
_PR_SCORES_UNCHANGED: dict[CVSSPrivilegesRequired, float] = {
    CVSSPrivilegesRequired.NONE: 0.85,
    CVSSPrivilegesRequired.LOW: 0.62,
    CVSSPrivilegesRequired.HIGH: 0.27,
}

_PR_SCORES_CHANGED: dict[CVSSPrivilegesRequired, float] = {
    CVSSPrivilegesRequired.NONE: 0.85,
    CVSSPrivilegesRequired.LOW: 0.50,
    CVSSPrivilegesRequired.HIGH: 0.27,
}

_UI_SCORES: dict[CVSSUserInteraction, float] = {
    CVSSUserInteraction.NONE: 0.85,
    CVSSUserInteraction.REQUIRED: 0.62,
}

_IMPACT_SCORES: dict[CVSSImpact, float] = {
    CVSSImpact.NONE: 0.00,
    CVSSImpact.LOW: 0.22,
    CVSSImpact.HIGH: 0.56,
}


# ---------------------------------------------------------------------------
# CVSS Vector dataclass
# ---------------------------------------------------------------------------


@dataclass
class CVSSVector:
    """All CVSS 3.1 Base Metric values for one vulnerability instance."""

    attack_vector: CVSSAttackVector
    attack_complexity: CVSSAttackComplexity
    privileges_required: CVSSPrivilegesRequired
    user_interaction: CVSSUserInteraction
    scope: CVSSScope
    confidentiality: CVSSImpact
    integrity: CVSSImpact
    availability: CVSSImpact


# ---------------------------------------------------------------------------
# Score calculation
# ---------------------------------------------------------------------------


def _roundup(value: float) -> float:
    """CVSS 3.1 Roundup function: round up to the nearest 0.1.

    Defined in the CVSS spec as: the smallest number, specified to 1 decimal
    place, that is equal to or higher than its input.
    """
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10.0


def calculate_base_score(vector: CVSSVector) -> float:
    """Compute the CVSS 3.1 Base Score for *vector*.

    Args:
        vector: A fully populated CVSSVector instance.

    Returns:
        Base score in the range [0.0, 10.0], rounded per CVSS spec.
    """
    c_val = _IMPACT_SCORES[vector.confidentiality]
    i_val = _IMPACT_SCORES[vector.integrity]
    a_val = _IMPACT_SCORES[vector.availability]

    # Impact Sub-Score (ISS)
    iss = 1.0 - (1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val)

    scope_changed = vector.scope == CVSSScope.CHANGED

    # Impact score
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    # Exploitability sub-score
    av = _AV_SCORES[vector.attack_vector]
    ac = _AC_SCORES[vector.attack_complexity]
    pr_table = _PR_SCORES_CHANGED if scope_changed else _PR_SCORES_UNCHANGED
    pr = pr_table[vector.privileges_required]
    ui = _UI_SCORES[vector.user_interaction]

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base_score = _roundup(min(impact + exploitability, 10.0))

    return base_score


# ---------------------------------------------------------------------------
# String representation
# ---------------------------------------------------------------------------


def vector_to_string(vector: CVSSVector) -> str:
    """Generate the CVSS 3.1 vector string (e.g. ``CVSS:3.1/AV:N/AC:L/...``).

    Args:
        vector: A fully populated CVSSVector instance.

    Returns:
        Standard CVSS vector string.
    """
    return (
        f"CVSS:3.1"
        f"/AV:{vector.attack_vector.value}"
        f"/AC:{vector.attack_complexity.value}"
        f"/PR:{vector.privileges_required.value}"
        f"/UI:{vector.user_interaction.value}"
        f"/S:{vector.scope.value}"
        f"/C:{vector.confidentiality.value}"
        f"/I:{vector.integrity.value}"
        f"/A:{vector.availability.value}"
    )
