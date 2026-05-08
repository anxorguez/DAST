"""Unit tests for BaseScanner encoding intersection logic."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analysis.models import RawFinding
from src.core.config import Settings
from src.fuzzing.base_scanner import BaseScanner
from src.vectors.models import AttackVector, SurfaceType, VulnType

# ---------------------------------------------------------------------------
# Minimal concrete subclass for testing
# ---------------------------------------------------------------------------


class _ScannerNoneOnly(BaseScanner):
    """Scanner that only supports the 'none' encoding (conservative default)."""

    VULN_TYPE = VulnType.XSS
    SUPPORTED_ENCODINGS = ("none",)

    async def _detect(
        self, vector: AttackVector, payload: str, encoding: str = "none"
    ) -> RawFinding | None:
        return None


class _ScannerNoneUrl(BaseScanner):
    """Scanner that supports none and url encodings."""

    VULN_TYPE = VulnType.SQLI
    SUPPORTED_ENCODINGS = ("none", "url")

    async def _detect(
        self, vector: AttackVector, payload: str, encoding: str = "none"
    ) -> RawFinding | None:
        return None


def _make_mock_http() -> MagicMock:
    client = MagicMock()
    client.get = AsyncMock(return_value=MagicMock(status_code=200, text="", headers={}))
    client.post = AsyncMock(return_value=MagicMock(status_code=200, text="", headers={}))
    client.get_no_retry = AsyncMock(return_value=MagicMock(status_code=200, text="", headers={}))
    client.post_no_retry = AsyncMock(return_value=MagicMock(status_code=200, text="", headers={}))
    return client


def _settings(obfuscation: str = "none") -> Settings:
    return Settings(
        target_url="http://localhost",
        output_dir="/tmp/dast",
        obfuscation=obfuscation,
    )


# ---------------------------------------------------------------------------
# _compute_effective_encodings tests
# ---------------------------------------------------------------------------


def test_effective_encodings_intersection_url_base64() -> None:
    """SUPPORTED=(none,url) ∩ requested=(url,base64) → (url,)."""
    scanner = _ScannerNoneUrl(_settings("url,base64"), _make_mock_http())
    effective = scanner._compute_effective_encodings()
    assert effective == ("url",)


def test_effective_encodings_fallback_when_empty_intersection() -> None:
    """SUPPORTED=(none,) ∩ requested=(base64,) → fallback to (none,)."""
    scanner = _ScannerNoneOnly(_settings("base64"), _make_mock_http())
    effective = scanner._compute_effective_encodings()
    assert effective == ("none",)


def test_effective_encodings_all_supported_kept() -> None:
    """If all requested encodings are supported, none are dropped."""
    scanner = _ScannerNoneUrl(_settings("none,url"), _make_mock_http())
    effective = scanner._compute_effective_encodings()
    assert set(effective) == {"none", "url"}


def test_effective_encodings_default_none() -> None:
    """Default obfuscation=none produces effective=(none,)."""
    scanner = _ScannerNoneUrl(_settings("none"), _make_mock_http())
    effective = scanner._compute_effective_encodings()
    assert effective == ("none",)


def test_effective_encodings_single_match() -> None:
    """Only the matching encoding is kept from a multi-encoding request."""
    scanner = _ScannerNoneUrl(_settings("url,double_url,base64"), _make_mock_http())
    effective = scanner._compute_effective_encodings()
    # double_url and base64 not in SUPPORTED_ENCODINGS → only url survives
    assert effective == ("url",)


# ---------------------------------------------------------------------------
# Validator dedup: raw payload (not encoded) is the dedup key
# ---------------------------------------------------------------------------


def test_raw_payload_stored_in_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    """_make_finding stores the raw (un-encoded) payload, not the wire form.

    This is critical for Validator dedup: two findings for the same raw payload
    with different encodings share the same key and are deduplicated to one.
    """
    mock_http = _make_mock_http()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "hello"
    mock_http.get.return_value = resp

    from src.analysis.models import Confidence
    from src.vectors.models import AttackVector

    vector = AttackVector(
        source_url="http://localhost/",
        target_url="http://localhost/",
        method="GET",
        field_name="q",
        surface=SurfaceType.URL_PARAM,
        field_context="q",
        extra_params={},
        priority=1,
        applicable_vulns=[VulnType.SQLI],
    )
    scanner = _ScannerNoneUrl(_settings(), mock_http)
    raw_payload = "' OR 1=1--"
    finding = scanner._make_finding(
        vector, raw_payload, resp, 50, Confidence.CONFIRMED, "evidence", "url"
    )
    # The raw payload (not url-encoded form) is stored.
    assert finding.payload == raw_payload
    # Encoding is recorded.
    assert finding.encoding == "url"
    # Evidence is prefixed with obfuscation tag.
    assert "[obfuscation=url]" in finding.evidence
