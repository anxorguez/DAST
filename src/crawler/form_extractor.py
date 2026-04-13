"""Extract and normalise HTML forms from a rendered page."""

from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from src.vectors.models import FormField, HTMLForm


def extract_forms(html: str, base_url: str) -> list[HTMLForm]:
    """Parse all <form> elements from *html* and return normalised HTMLForm objects.

    Args:
        html: The fully rendered HTML content of the page.
        base_url: Canonical URL of the page, used to resolve relative action URLs.

    Returns:
        A list of HTMLForm instances. Forms with zero injectable fields are excluded.
    """
    soup = BeautifulSoup(html, "lxml")
    forms: list[HTMLForm] = []

    for form_tag in soup.find_all("form"):
        if not isinstance(form_tag, Tag):
            continue

        raw_action = form_tag.get("action", "")
        action_url = urljoin(base_url, str(raw_action)) if raw_action else base_url
        method = str(form_tag.get("method", "get")).upper()
        enctype = str(form_tag.get("enctype", "application/x-www-form-urlencoded"))

        fields = _extract_fields(form_tag)
        if fields:
            forms.append(
                HTMLForm(
                    action_url=action_url,
                    method=method,
                    fields=fields,
                    enctype=enctype,
                )
            )

    return forms


def _extract_fields(form_tag: Tag) -> list[FormField]:
    """Return FormField objects for every named field inside a form."""
    fields: list[FormField] = []

    for tag in form_tag.find_all(["input", "textarea", "select"]):
        if not isinstance(tag, Tag):
            continue

        name = tag.get("name")
        if not name:
            continue

        field_type = _get_field_type(tag)
        default_value = _get_default_value(tag)
        options = _get_options(tag)

        fields.append(
            FormField(
                name=str(name),
                field_type=field_type,
                default_value=default_value,
                options=options,
            )
        )

    return fields


def _get_field_type(tag: Tag) -> str:
    if tag.name == "textarea":
        return "textarea"
    if tag.name == "select":
        return "select"
    return str(tag.get("type", "text")).lower()


def _get_default_value(tag: Tag) -> str | None:
    if tag.name == "textarea":
        text = tag.get_text()
        return text.strip() if text.strip() else None
    raw = tag.get("value", "")
    return str(raw) if raw else None


def _get_options(tag: Tag) -> list[str]:
    if tag.name != "select":
        return []
    opts: list[str] = []
    for opt in tag.find_all("option"):
        if not isinstance(opt, Tag):
            continue
        val = opt.get("value")
        opts.append(str(val) if val is not None else opt.get_text().strip())
    return opts
