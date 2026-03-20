"""Unit tests for the VectorAnalyzer module."""

from __future__ import annotations

from datetime import datetime

import pytest

from src.vectors.models import (
    AttackVector,
    CrawledPage,
    FormField,
    HTMLForm,
    SurfaceType,
    VulnType,
)
from src.vectors.vector_analyzer import VectorAnalyzer


def _make_page(url: str, forms: list[HTMLForm], links: list[str] | None = None) -> CrawledPage:
    return CrawledPage(
        url=url,
        html="",
        forms=forms,
        links=links or [],
        status_code=200,
        crawled_at=datetime.utcnow(),
    )


def _make_form(action: str, method: str, fields: list[FormField]) -> HTMLForm:
    return HTMLForm(action_url=action, method=method, fields=fields)


class TestVectorAnalyzer:
    def setup_method(self) -> None:
        self.analyzer = VectorAnalyzer()

    def test_extracts_form_field_vector(self) -> None:
        form = _make_form(
            "http://localhost/search",
            "GET",
            [FormField(name="q", field_type="text")],
        )
        page = _make_page("http://localhost/search", [form])
        vectors = self.analyzer.analyze([page])
        assert len(vectors) >= 1
        assert any(v.field_name == "q" for v in vectors)

    def test_deduplicates_vectors(self) -> None:
        form = _make_form(
            "http://localhost/search",
            "GET",
            [FormField(name="q", field_type="text")],
        )
        page1 = _make_page("http://localhost/", [form])
        page2 = _make_page("http://localhost/other", [form])
        vectors = self.analyzer.analyze([page1, page2])
        keys = [(v.target_url, v.method, v.field_name) for v in vectors]
        assert len(keys) == len(set(keys))

    def test_skips_submit_fields(self) -> None:
        form = _make_form(
            "http://localhost/form",
            "POST",
            [
                FormField(name="data", field_type="text"),
                FormField(name="go", field_type="submit"),
            ],
        )
        page = _make_page("http://localhost/form", [form])
        vectors = self.analyzer.analyze([page])
        field_names = [v.field_name for v in vectors]
        assert "go" not in field_names

    def test_cmdi_hint_adds_cmdi_vulntype(self) -> None:
        form = _make_form(
            "http://localhost/exec",
            "POST",
            [FormField(name="cmd", field_type="text")],
        )
        page = _make_page("http://localhost/exec", [form])
        vectors = self.analyzer.analyze([page])
        cmd_vectors = [v for v in vectors if v.field_name == "cmd"]
        assert cmd_vectors
        assert VulnType.CMDI in cmd_vectors[0].vuln_types

    def test_hidden_field_gets_only_sqli(self) -> None:
        form = _make_form(
            "http://localhost/form",
            "POST",
            [FormField(name="id", field_type="hidden", default_value="1")],
        )
        page = _make_page("http://localhost/form", [form])
        vectors = self.analyzer.analyze([page])
        id_vectors = [v for v in vectors if v.field_name == "id"]
        assert id_vectors
        assert id_vectors[0].vuln_types == [VulnType.SQLI]

    def test_url_params_extracted(self) -> None:
        page = _make_page("http://localhost/search?q=hello&page=1", [])
        vectors = self.analyzer.analyze([page])
        field_names = {v.field_name for v in vectors}
        assert "q" in field_names
        assert "page" in field_names

    def test_returns_empty_for_no_pages(self) -> None:
        assert self.analyzer.analyze([]) == []
