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
