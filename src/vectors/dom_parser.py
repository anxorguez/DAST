"""Minimal BeautifulSoup4/lxml wrapper for structured DOM queries."""

from __future__ import annotations

from bs4 import BeautifulSoup, Tag


class DOMParser:
    """Wraps a single HTML document for structured querying.

    Uses lxml as the backend parser (faster; more lenient with malformed HTML
    than the html.parser stdlib variant).

    Args:
        html: Rendered HTML content as a string.
    """

    def __init__(self, html: str) -> None:
        self._soup = BeautifulSoup(html, "lxml")

    def find_forms(self) -> list[Tag]:
        """Return all <form> elements in the document."""
        return [t for t in self._soup.find_all("form") if isinstance(t, Tag)]

    def find_inputs_in(self, form: Tag) -> list[Tag]:
        """Return all input/textarea/select elements inside *form*."""
        return [
            t
            for t in form.find_all(["input", "textarea", "select"])
            if isinstance(t, Tag)
        ]

    def find_links(self) -> list[str]:
        """Return the raw href values of all <a href=...> elements."""
        hrefs: list[str] = []
        for tag in self._soup.find_all("a", href=True):
            if isinstance(tag, Tag):
                hrefs.append(str(tag["href"]))
        return hrefs

    def find_event_handlers(self) -> list[tuple[str, str]]:
        """Return (event_name, handler_code) pairs for all inline event handlers."""
        events = [
            "onclick", "onsubmit", "onchange",
            "onload", "onerror", "onmouseover",
            "onfocus", "oninput",
        ]
        result: list[tuple[str, str]] = []
        for event in events:
            for tag in self._soup.find_all(attrs={event: True}):
                if isinstance(tag, Tag):
                    result.append((event, str(tag.get(event, ""))))
        return result

    def contains_text(self, text: str) -> bool:
        """Return True if *text* appears anywhere in the raw HTML source."""
        return text in str(self._soup)

    def get_text(self) -> str:
        """Return all visible text content joined with spaces."""
        return self._soup.get_text(separator=" ", strip=True)

    def get_raw_html(self) -> str:
        """Return the serialised HTML."""
        return str(self._soup)
