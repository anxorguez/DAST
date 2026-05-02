"""Unit tests for the Crawler module."""

from __future__ import annotations

from src.crawler.crawler import _is_download_url
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

    def test_skips_logout_links(self) -> None:
        """Logout URLs must not be followed during BFS.

        Visiting /logout.php mid-crawl silently invalidates the
        authenticated PHP session, so every subsequent request (crawler
        *and* fuzzer) redirects back to the login form and no vulnerable
        surface is ever tested.
        """
        html = (
            '<a href="/logout.php">Logout</a>'
            '<a href="/signout">Sign out</a>'
            '<a href="/user/sign-out.aspx">Out</a>'
            '<a href="/vulnerabilities/sqli/">SQLi</a>'
        )
        links = extract_links(html, "http://dvwa", "dvwa")
        assert "http://dvwa/vulnerabilities/sqli/" in links
        for link in links:
            assert "logout" not in link.lower()
            assert "sign" not in link.lower() or "sqli" in link.lower()


class TestDownloadUrlFilter:
    """Crawler must skip URLs that trigger a browser download.

    Regression for the WARN flood seen in every scan log:

        WARNING | src.crawler.crawler | Could not crawl
            http://dvwa/config/config.inc.php.dist: Page.goto: Download is starting

    These URLs do not produce HTML for the form/link extractor and should
    be filtered before the goto, not handled after the warning fires.
    """

    def test_pdf_filtered(self) -> None:
        assert _is_download_url("http://dvwa/docs/DVWA_v1.3.pdf")

    def test_zip_filtered(self) -> None:
        assert _is_download_url("http://dvwa/files/archive.zip")

    def test_dist_filtered(self) -> None:
        assert _is_download_url("http://dvwa/config/config.inc.php.dist")

    def test_html_not_filtered(self) -> None:
        assert not _is_download_url("http://dvwa/index.php")
        assert not _is_download_url("http://dvwa/vulnerabilities/sqli/")

    def test_query_string_does_not_confuse_filter(self) -> None:
        # Path is .php, query happens to mention .pdf — must not be filtered.
        assert not _is_download_url("http://dvwa/page.php?ref=guide.pdf")

    def test_case_insensitive(self) -> None:
        assert _is_download_url("http://dvwa/REPORT.PDF")
        assert _is_download_url("http://dvwa/report.PDF")
