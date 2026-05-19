"""Tests for the 'unlimited' value across coverage CLI flags."""

from __future__ import annotations

import click
import pytest

from src.core.cli_types import UNLIMITED_INT
from src.core.config import get_settings
from src.fuzzing.payload_loader import PayloadLoader
from src.vectors.models import VulnType


class TestUnlimitedIntType:
    @pytest.mark.parametrize("raw", ["unlimited", "none", "inf", "-1", "UNLIMITED", "Inf"])
    def test_sentinels_map_to_none(self, raw: str) -> None:
        assert UNLIMITED_INT.convert(raw, None, None) is None

    @pytest.mark.parametrize("raw, expected", [("1", 1), ("50", 50), ("9999", 9999)])
    def test_positive_int_passes_through(self, raw: str, expected: int) -> None:
        assert UNLIMITED_INT.convert(raw, None, None) == expected

    @pytest.mark.parametrize("raw", ["0", "-2", "abc", ""])
    def test_invalid_values_fail(self, raw: str) -> None:
        with pytest.raises(click.exceptions.BadParameter):
            UNLIMITED_INT.convert(raw, None, None)

    def test_none_input_returns_none(self) -> None:
        assert UNLIMITED_INT.convert(None, None, None) is None


class TestSettingsAcceptNone:
    def test_coverage_fields_accept_none(self) -> None:
        s = get_settings(
            target_url="http://example.invalid",
            max_depth=None,
            max_pages=None,
            max_payloads_per_vector=None,
            scanner_vector_timeout_seconds=None,
        )
        assert s.max_depth is None
        assert s.max_pages is None
        assert s.max_payloads_per_vector is None
        assert s.scanner_vector_timeout_seconds is None

    def test_coverage_fields_accept_int(self) -> None:
        s = get_settings(
            target_url="http://example.invalid",
            max_depth=5,
            max_pages=200,
            max_payloads_per_vector=100,
            scanner_vector_timeout_seconds=60,
        )
        assert s.max_depth == 5
        assert s.max_pages == 200
        assert s.max_payloads_per_vector == 100
        assert s.scanner_vector_timeout_seconds == 60


class TestPayloadLoaderUnlimited:
    def test_max_count_none_returns_all(self) -> None:
        loader = PayloadLoader()
        all_payloads = loader.load(VulnType.XSS, max_count=None)
        capped = loader.load(VulnType.XSS, max_count=5)
        assert len(capped) == 5
        assert len(all_payloads) > len(capped)

    def test_load_subtype_none_returns_all(self) -> None:
        loader = PayloadLoader()
        all_payloads = loader.load_subtype(VulnType.SQLI, "error_based", max_count=None)
        capped = loader.load_subtype(VulnType.SQLI, "error_based", max_count=3)
        assert len(capped) == 3
        assert len(all_payloads) >= len(capped)
