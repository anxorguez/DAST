"""Unit tests for CVSS 3.1 Base Score calculation.

Reference scores verified against the CVSS 3.1 calculator at
https://www.first.org/cvss/calculator/3.1
"""

from __future__ import annotations

import pytest

from src.analysis.cvss import (
    CVSSAttackComplexity,
    CVSSAttackVector,
    CVSSImpact,
    CVSSPrivilegesRequired,
    CVSSScope,
    CVSSUserInteraction,
    CVSSVector,
    calculate_base_score,
    vector_to_string,
)


def _vec(
    av: CVSSAttackVector = CVSSAttackVector.NETWORK,
    ac: CVSSAttackComplexity = CVSSAttackComplexity.LOW,
    pr: CVSSPrivilegesRequired = CVSSPrivilegesRequired.NONE,
    ui: CVSSUserInteraction = CVSSUserInteraction.NONE,
    s: CVSSScope = CVSSScope.UNCHANGED,
    c: CVSSImpact = CVSSImpact.NONE,
    i: CVSSImpact = CVSSImpact.NONE,
    a: CVSSImpact = CVSSImpact.NONE,
) -> CVSSVector:
    return CVSSVector(
        attack_vector=av,
        attack_complexity=ac,
        privileges_required=pr,
        user_interaction=ui,
        scope=s,
        confidentiality=c,
        integrity=i,
        availability=a,
    )


class TestCalculateBaseScore:
    """Known CVSS 3.1 scores from the FIRST calculator and published CVEs."""

    def test_zero_impact_returns_zero(self) -> None:
        """All impacts None → score 0.0."""
        score = calculate_base_score(_vec())
        assert score == 0.0

    def test_sqli_error_based(self) -> None:
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 9.1."""
        v = _vec(c=CVSSImpact.HIGH, i=CVSSImpact.HIGH)
        score = calculate_base_score(v)
        assert score == pytest.approx(9.1, abs=0.05)

    def test_cmdi_full_impact(self) -> None:
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8."""
        v = _vec(c=CVSSImpact.HIGH, i=CVSSImpact.HIGH, a=CVSSImpact.HIGH)
        score = calculate_base_score(v)
        assert score == pytest.approx(9.8, abs=0.05)

    def test_xss_reflected(self) -> None:
        """AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N → 6.1."""
        v = _vec(
            ui=CVSSUserInteraction.REQUIRED,
            s=CVSSScope.CHANGED,
            c=CVSSImpact.LOW,
            i=CVSSImpact.LOW,
        )
        score = calculate_base_score(v)
        assert score == pytest.approx(6.1, abs=0.05)

    def test_xss_stored(self) -> None:
        """AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N → 4.8 per CVSS 3.1 spec formula."""
        v = _vec(
            pr=CVSSPrivilegesRequired.LOW,
            ui=CVSSUserInteraction.REQUIRED,
            s=CVSSScope.CHANGED,
            c=CVSSImpact.LOW,
            i=CVSSImpact.LOW,
        )
        score = calculate_base_score(v)
        assert score == pytest.approx(4.8, abs=0.05)

    def test_sqli_time_based(self) -> None:
        """AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N → 3.7."""
        v = _vec(
            ac=CVSSAttackComplexity.HIGH,
            c=CVSSImpact.LOW,
        )
        score = calculate_base_score(v)
        assert score == pytest.approx(3.7, abs=0.05)

    def test_path_traversal(self) -> None:
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5."""
        v = _vec(c=CVSSImpact.HIGH)
        score = calculate_base_score(v)
        assert score == pytest.approx(7.5, abs=0.05)

    def test_local_av_reduces_score(self) -> None:
        """Local AV should produce a lower score than Network AV."""
        network = calculate_base_score(_vec(c=CVSSImpact.HIGH, i=CVSSImpact.HIGH))
        local = calculate_base_score(
            _vec(av=CVSSAttackVector.LOCAL, c=CVSSImpact.HIGH, i=CVSSImpact.HIGH)
        )
        assert local < network

    def test_score_capped_at_10(self) -> None:
        """Maximum possible score is 10.0."""
        v = _vec(
            s=CVSSScope.CHANGED,
            c=CVSSImpact.HIGH,
            i=CVSSImpact.HIGH,
            a=CVSSImpact.HIGH,
        )
        assert calculate_base_score(v) <= 10.0


class TestVectorToString:
    """Tests for the CVSS vector string serialisation."""

    def test_network_no_impact_string(self) -> None:
        v = _vec()
        s = vector_to_string(v)
        assert s == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

    def test_cmdi_string(self) -> None:
        v = _vec(c=CVSSImpact.HIGH, i=CVSSImpact.HIGH, a=CVSSImpact.HIGH)
        s = vector_to_string(v)
        assert s == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_xss_reflected_string(self) -> None:
        v = _vec(
            ui=CVSSUserInteraction.REQUIRED,
            s=CVSSScope.CHANGED,
            c=CVSSImpact.LOW,
            i=CVSSImpact.LOW,
        )
        s = vector_to_string(v)
        assert s == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

    def test_string_starts_with_cvss_prefix(self) -> None:
        s = vector_to_string(_vec())
        assert s.startswith("CVSS:3.1/")
