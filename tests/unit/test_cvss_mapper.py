"""Unit tests for cvss_mapper.map_finding_to_cvss."""

from __future__ import annotations

import pytest

from src.analysis.cvss import (
    CVSSAttackComplexity,
    CVSSAttackVector,
    CVSSScope,
    CVSSUserInteraction,
    calculate_base_score,
)
from src.analysis.cvss_mapper import map_finding_to_cvss
from src.analysis.models import Confidence, RawFinding
from src.vectors.models import AttackVector, SurfaceType, VulnType


def _make_raw(
    vuln_type: VulnType,
    payload: str = "test",
    surface: SurfaceType = SurfaceType.FORM_FIELD,
) -> RawFinding:
    vector = AttackVector(
        source_url="http://localhost/",
        target_url="http://localhost/submit",
        method="POST",
        surface=surface,
        field_name="q",
        field_context="<form>",
        applicable_vulns=[vuln_type],
    )
    return RawFinding(
        vector=vector,
        vuln_type=vuln_type,
        payload=payload,
        response_snippet="...",
        confidence=Confidence.CONFIRMED,
        evidence="test",
    )


class TestMapFindingToCvss:
    def test_sqli_error_based_is_network_low(self) -> None:
        raw = _make_raw(VulnType.SQLI, payload="' OR 1=1--")
        cvss = map_finding_to_cvss(raw)
        assert cvss.attack_vector == CVSSAttackVector.NETWORK
        assert cvss.attack_complexity == CVSSAttackComplexity.LOW

    def test_sqli_time_based_is_high_complexity(self) -> None:
        raw = _make_raw(VulnType.SQLI, payload="'; WAITFOR DELAY '0:0:5'--")
        cvss = map_finding_to_cvss(raw)
        assert cvss.attack_complexity == CVSSAttackComplexity.HIGH

    def test_xss_reflected_requires_user_interaction(self) -> None:
        raw = _make_raw(VulnType.XSS, payload="<script>alert(1)</script>")
        cvss = map_finding_to_cvss(raw)
        assert cvss.user_interaction == CVSSUserInteraction.REQUIRED
        assert cvss.scope == CVSSScope.CHANGED

    def test_xss_stored_requires_low_privileges(self) -> None:
        raw = _make_raw(
            VulnType.XSS,
            payload="<script>alert(1)</script>",
            surface=SurfaceType.STORED,
        )
        from src.analysis.cvss import CVSSPrivilegesRequired

        cvss = map_finding_to_cvss(raw)
        assert cvss.privileges_required == CVSSPrivilegesRequired.LOW

    def test_cmdi_full_impact(self) -> None:
        from src.analysis.cvss import CVSSImpact

        raw = _make_raw(VulnType.CMDI)
        cvss = map_finding_to_cvss(raw)
        assert cvss.confidentiality == CVSSImpact.HIGH
        assert cvss.integrity == CVSSImpact.HIGH
        assert cvss.availability == CVSSImpact.HIGH

    def test_ssrf_produces_valid_cvss(self) -> None:
        raw = _make_raw(VulnType.SSRF)
        cvss = map_finding_to_cvss(raw)
        score = calculate_base_score(cvss)
        assert 0.0 < score <= 10.0

    def test_xxe_produces_valid_cvss(self) -> None:
        raw = _make_raw(VulnType.XXE)
        cvss = map_finding_to_cvss(raw)
        score = calculate_base_score(cvss)
        assert score >= 7.0

    def test_deserialization_full_impact(self) -> None:
        from src.analysis.cvss import CVSSImpact

        raw = _make_raw(VulnType.DESERIALIZATION)
        cvss = map_finding_to_cvss(raw)
        assert cvss.confidentiality == CVSSImpact.HIGH
        assert cvss.integrity == CVSSImpact.HIGH
        assert cvss.availability == CVSSImpact.HIGH

    def test_path_traversal_confidentiality_high(self) -> None:
        from src.analysis.cvss import CVSSImpact

        raw = _make_raw(VulnType.PATH_TRAVERSAL)
        cvss = map_finding_to_cvss(raw)
        assert cvss.confidentiality == CVSSImpact.HIGH

    def test_open_redirect_scope_changed(self) -> None:
        raw = _make_raw(VulnType.OPEN_REDIRECT)
        cvss = map_finding_to_cvss(raw)
        assert cvss.scope == CVSSScope.CHANGED
        assert cvss.user_interaction == CVSSUserInteraction.REQUIRED

    @pytest.mark.parametrize("vuln_type", list(VulnType))
    def test_all_vuln_types_produce_valid_score(self, vuln_type: VulnType) -> None:
        """Every VulnType should map to a valid CVSS vector without raising."""
        raw = _make_raw(vuln_type)
        cvss = map_finding_to_cvss(raw)
        score = calculate_base_score(cvss)
        assert 0.0 <= score <= 10.0
