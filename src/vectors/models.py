"""Shared data models for the DAST pipeline.

CrawledPage and HTMLForm/FormField are produced by the Crawler module.
AttackVector is produced by the Vector Identification module.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class SurfaceType(str, Enum):
    """Classification of the attack surface for a given vector."""

    FORM_FIELD = "form_field"
    URL_PARAM = "url_param"
    PATH_PARAM = "path_param"
    HTTP_HEADER = "http_header"
    JSON_BODY = "json_body"
    STORED = "stored"  # Synthetic surface used for stored-XSS second-pass findings


class VulnType(str, Enum):
    """Vulnerability class tested by the fuzzing engine."""

    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"


# ---------------------------------------------------------------------------
# Crawler output models
# ---------------------------------------------------------------------------


@dataclass
class FormField:
    """A single field within an HTML form."""

    name: str
    field_type: str  # "text", "hidden", "password", "select", "textarea", …
    default_value: str | None = None
    options: list[str] = field(default_factory=list)


@dataclass
class HTMLForm:
    """A parsed HTML form element."""

    action_url: str
    method: str  # "GET" or "POST"
    fields: list[FormField] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"


@dataclass
class CrawledPage:
    """All data extracted from a single visited page."""

    url: str
    html_content: str
    forms: list[HTMLForm] = field(default_factory=list)
    internal_links: list[str] = field(default_factory=list)
    xhr_endpoints: list[str] = field(default_factory=list)
    depth: int = 0
    crawled_at: datetime = field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Vector identification output models
# ---------------------------------------------------------------------------


@dataclass
class AttackVector:
    """A single injectable parameter identified in the target application."""

    source_url: str
    target_url: str
    method: str  # "GET" or "POST"
    surface: SurfaceType
    field_name: str
    field_context: str  # Short HTML snippet for the report
    applicable_vulns: list[VulnType] = field(default_factory=list)
    priority: int = 2  # 1 = high, 2 = medium, 3 = low
    extra_params: dict[str, str] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
