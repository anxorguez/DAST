"""Unit tests for the VectorAnalyzer module."""

from __future__ import annotations

from datetime import datetime

from src.vectors.models import (
    CrawledPage,
    FormField,
    HTMLForm,
    VulnType,
)
from src.vectors.vector_analyzer import VectorAnalyzer


def _make_page(url: str, forms: list[HTMLForm], links: list[str] | None = None) -> CrawledPage:
    return CrawledPage(
        url=url,
        html_content="",
        forms=forms,
        internal_links=links or [],
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

    def test_submit_button_preserved_in_extra_params(self) -> None:
        """Submit values must stay in extra_params so PHP apps reach the vulnerable branch.

        DVWA and many other PHP apps gate their SQL/XSS/CMDi code with
        isset($_GET['Submit']). If the fuzzer drops that parameter, the
        vulnerable branch never runs and scanners see 0 findings.
        """
        form = _make_form(
            "http://localhost/vulnerabilities/sqli/",
            "GET",
            [
                FormField(name="id", field_type="text"),
                FormField(name="Submit", field_type="submit", default_value="Submit"),
                FormField(name="user_token", field_type="hidden", default_value="abc123"),
            ],
        )
        page = _make_page("http://localhost/vulnerabilities/sqli/", [form])
        vectors = self.analyzer.analyze([page])
        id_vectors = [v for v in vectors if v.field_name == "id"]
        assert id_vectors, "id vector must be extracted"
        extras = id_vectors[0].extra_params
        assert extras.get("Submit") == "Submit", (
            "Submit button must be preserved in extra_params so PHP apps "
            "gated by isset($_GET['Submit']) reach the vulnerable branch"
        )
        assert extras.get("user_token") == "abc123"

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
        assert VulnType.CMDI in cmd_vectors[0].applicable_vulns

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
        assert id_vectors[0].applicable_vulns == [VulnType.SQLI]

    def test_url_params_extracted(self) -> None:
        page = _make_page("http://localhost/search?q=hello&page=1", [])
        vectors = self.analyzer.analyze([page])
        field_names = {v.field_name for v in vectors}
        assert "q" in field_names
        assert "page" in field_names

    def test_returns_empty_for_no_pages(self) -> None:
        assert self.analyzer.analyze([]) == []

    def test_blacklisted_form_action_is_skipped(self) -> None:
        """Forms posting to instructions.php / setup.php must produce no vectors.

        Background: DVWA exposes ``instructions.php?doc=...`` (file include
        for documentation) and ``setup.php`` (resets the database on every
        request).  Fuzzing either is pointless and actively destabilises the
        scan target; the blacklist filters them at the analyzer stage.
        """
        form = _make_form(
            "http://localhost/instructions.php",
            "GET",
            [FormField(name="doc", field_type="text")],
        )
        page = _make_page("http://localhost/instructions.php", [form])
        vectors = self.analyzer.analyze([page])
        assert vectors == []

    def test_blacklisted_url_params_are_skipped(self) -> None:
        """URL-param vectors on a blacklisted path must not be emitted."""
        page = _make_page("http://localhost/instructions.php?doc=changelog", [])
        vectors = self.analyzer.analyze([page])
        assert vectors == []

    def test_blacklist_does_not_drop_normal_pages(self) -> None:
        """Sanity: a normal page with the same param name still produces a vector."""
        page = _make_page("http://localhost/search.php?doc=hello", [])
        vectors = self.analyzer.analyze([page])
        assert any(v.field_name == "doc" for v in vectors)

    def test_security_setup_phpinfo_paths_are_blacklisted(self) -> None:
        """All admin/info endpoints listed in the blacklist must be filtered."""
        for path in ("/security.php", "/setup.php", "/phpinfo.php"):
            form = _make_form(
                f"http://localhost{path}",
                "POST",
                [FormField(name="x", field_type="text")],
            )
            page = _make_page(f"http://localhost{path}", [form])
            vectors = self.analyzer.analyze([page])
            assert vectors == [], f"{path} should be blacklisted"
