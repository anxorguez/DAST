"""Unit tests for PayloadLoader."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.exceptions import PayloadLoadError
from src.fuzzing.payload_loader import PayloadLoader
from src.vectors.models import VulnType


class TestPayloadLoader:
    def setup_method(self) -> None:
        self.loader = PayloadLoader()

    def test_loads_sqli_payloads(self) -> None:
        payloads = self.loader.load(VulnType.SQLI, max_count=200)
        assert len(payloads) > 0
        # Every payload must be a non-empty string with no leading '#'
        for p in payloads:
            assert p and not p.startswith("#")

    def test_loads_xss_payloads(self) -> None:
        payloads = self.loader.load(VulnType.XSS, max_count=200)
        assert len(payloads) > 0

    def test_loads_cmdi_payloads(self) -> None:
        payloads = self.loader.load(VulnType.CMDI, max_count=200)
        assert len(payloads) > 0

    def test_max_count_respected(self) -> None:
        payloads = self.loader.load(VulnType.SQLI, max_count=5)
        assert len(payloads) <= 5

    def test_deduplication(self) -> None:
        payloads = self.loader.load(VulnType.SQLI, max_count=500)
        assert len(payloads) == len(set(payloads))

    def test_load_subtype_error_based(self) -> None:
        payloads = self.loader.load_subtype(VulnType.SQLI, "error_based", max_count=100)
        assert len(payloads) > 0

    def test_load_subtype_missing_returns_empty(self) -> None:
        payloads = self.loader.load_subtype(VulnType.SQLI, "nonexistent_subtype")
        assert payloads == []

    def test_raises_on_missing_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import src.fuzzing.payload_loader as pl_module

        monkeypatch.setattr(pl_module, "_PAYLOAD_BASE", tmp_path)
        loader = PayloadLoader()
        with pytest.raises(PayloadLoadError):
            loader.load(VulnType.SQLI)

    def test_comments_excluded(self) -> None:
        payloads = self.loader.load(VulnType.SQLI, max_count=500)
        for p in payloads:
            assert not p.startswith("#")

    def test_blank_lines_excluded(self) -> None:
        payloads = self.loader.load(VulnType.SQLI, max_count=500)
        for p in payloads:
            assert p.strip() != ""

    def test_sqli_payload_order_is_cost_ascending(self) -> None:
        """SQLi payloads must be returned cheap-first to make the per-vector
        timeout budget meaningful: boolean → error → union → time.

        Regression for the case where time-based payloads (SLEEP/BENCHMARK)
        consumed the whole 120 s budget on /sqli/[id], leaving the real
        UNION/error-based detections out of the report entirely.
        """
        all_payloads = self.loader.load(VulnType.SQLI, max_count=500)

        boolean = self.loader.load_subtype(VulnType.SQLI, "blind_boolean", max_count=500)
        error = self.loader.load_subtype(VulnType.SQLI, "error_based", max_count=500)
        union = self.loader.load_subtype(VulnType.SQLI, "union_based", max_count=500)
        time_ = self.loader.load_subtype(VulnType.SQLI, "time_based", max_count=500)

        # Index of the *first* payload from each subtype in the merged list.
        def first_index_of(subset: list[str]) -> int:
            for i, p in enumerate(all_payloads):
                if p in subset:
                    return i
            return len(all_payloads)

        idx_boolean = first_index_of(boolean)
        idx_error = first_index_of(error)
        idx_union = first_index_of(union)
        idx_time = first_index_of(time_)

        assert idx_boolean < idx_time, "boolean must precede time-based"
        assert idx_error < idx_time, "error-based must precede time-based"
        assert idx_union < idx_time, "UNION-based must precede time-based"
