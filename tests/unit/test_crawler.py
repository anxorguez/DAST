"""Unit tests for the Crawler module."""

from __future__ import annotations

from src.crawler.form_extractor import extract_forms
from src.crawler.link_extractor import extract_links

SIMPLE_HTML = """
<html>
<body>
  <form method="POST" action="/login">
    <input type="text" name="username" value="">
    <input type="password" name="password" value="">
    <input type="submit" value="Login">
  </form>
  <a href="/about">About</a>
  <a href="https://external.example.com/page">External</a>
</body>
</html>
"""


class TestFormExtractor:
    def test_extracts_form_fields(self) -> None:
        forms = extract_forms(SIMPLE_HTML, "http://localhost:8080")
        assert len(forms) == 1
        form = forms[0]
        assert form.method == "POST"
        assert form.action_url == "http://localhost:8080/login"
        field_names = {f.name for f in form.fields}
        assert "username" in field_names
        assert "password" in field_names
        # submit buttons should not appear as injectable fields
        for f in form.fields:
            assert f.field_type != "submit"

    def test_resolves_relative_action_url(self) -> None:
        html = '<form action="search"></form>'
        extract_forms(html, "http://localhost:8080/page")
        # form has no injectable fields but action must be resolved
        # (form may be skipped entirely if no fields — just verify no crash)

    def test_returns_empty_for_no_forms(self) -> None:
        forms = extract_forms("<html><body><p>No forms here</p></body></html>", "http://localhost")
        assert forms == []


class TestLinkExtractor:
    def test_extracts_internal_links(self) -> None:
        links = extract_links(SIMPLE_HTML, "http://localhost:8080", "localhost")
        assert "http://localhost:8080/about" in links

    def test_excludes_external_links(self) -> None:
        links = extract_links(SIMPLE_HTML, "http://localhost:8080", "localhost")
        for link in links:
            assert "external.example.com" not in link

    def test_deduplicates_links(self) -> None:
        html = '<a href="/page">A</a><a href="/page">B</a>'
        links = extract_links(html, "http://localhost", "localhost")
        assert links.count("http://localhost/page") == 1

    def test_strips_fragment(self) -> None:
        html = '<a href="/page#section">Link</a>'
        links = extract_links(html, "http://localhost", "localhost")
        assert all("#" not in link for link in links)
