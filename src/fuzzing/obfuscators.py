"""Payload obfuscation transforms used by the fuzzer.

Each function takes a raw payload string and returns the transformed string.
The transforms are pure (no I/O, no state) so they can be unit-tested in
isolation and applied at request-build time inside BaseScanner._send.

See ``reports/docs/prompts/obfuscation_url_base64.md`` for the rationale on
why ``url`` requires the caller to bypass httpx auto-encoding while
``double_url`` and ``base64`` do not.
"""

from __future__ import annotations

import base64 as _b64
from typing import Final
from urllib.parse import quote

# Public encoding identifiers.  Keep this tuple and the dispatcher in sync
# with the ``--obfuscation`` CLI flag and with each scanner's
# SUPPORTED_ENCODINGS class constant.
ENCODING_NONE: Final[str] = "none"
ENCODING_URL: Final[str] = "url"
ENCODING_DOUBLE_URL: Final[str] = "double_url"
ENCODING_BASE64: Final[str] = "base64"
ENCODING_SQL_COMMENT: Final[str] = "sql_comment"

ALL_ENCODINGS: Final[tuple[str, ...]] = (
    ENCODING_NONE,
    ENCODING_URL,
    ENCODING_DOUBLE_URL,
    ENCODING_BASE64,
    ENCODING_SQL_COMMENT,
)


def url_encode(payload: str) -> str:
    """Single percent-encoding. Caller MUST send the result verbatim, bypassing
    httpx auto-encoding, otherwise the ``%`` characters get re-encoded and the
    wire form becomes double-encoded by accident."""
    # safe="" so reserved chars (=, &, /, etc.) are encoded too.
    return quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    """Apply percent-encoding twice.

    The result MUST be sent verbatim (bypassing httpx auto-encoding), exactly
    like ``url_encode``.  ``base_scanner._send`` handles this: the ``else``
    branch builds the query string manually for both ``url`` and ``double_url``.

    **Wire form for ``' OR 1=1``:** ``%2527%2520OR%25201%253D1``

    **Application-layer note:** PHP ``parse_str`` / ``$_GET`` performs a
    single URL-decode.  The above wire value decodes to ``%27%20OR%201%3D1``
    inside PHP — a literal string, not an injection fragment.  This means
    ``double_url`` is a **WAF-bypass technique** (the WAF sees ``%25xx`` and
    does not detect ``'``), not an application-layer injection technique.
    Use it to demonstrate that payloads reach the application unblocked, not
    to produce findings.

    Metric to track: ``blocked_by_layer.waf_crs(double_url)`` should be
    significantly lower than ``blocked_by_layer.waf_crs(none)`` — ideally
    close to 1.0× rather than 2.0×.
    """
    return quote(quote(payload, safe=""), safe="")


def base64_encode(payload: str) -> str:
    """UTF-8 → base64 (standard alphabet, with padding)."""
    return _b64.b64encode(payload.encode("utf-8")).decode("ascii")


def sql_comment_encode(payload: str) -> str:
    """Insert SQL inline comments (/**/) between whitespace-separated tokens.

    MySQL (and MariaDB) treat ``/**/`` as whitespace inside SQL statements, so
    ``'/**/OR/**/1=1--`` executes identically to ``' OR 1=1--``.  However,
    OWASP CRS regex signatures typically look for contiguous patterns like
    ``\\bOR\\s+\\d`` or ``UNION\\s+SELECT``, which no longer match when the
    tokens are separated by ``/**/``.

    **Wire form:** the result is sent verbatim (same branch as ``none`` in
    ``base_scanner._send``), because the payload does not contain URL-encoded
    characters and httpx's normal params/data path is correct.

    **Limitation:** does not re-encode the payload for URL transport (the
    caller may combine with ``url`` encoding for GET parameters if needed).
    Only applies to whitespace boundaries — does not insert comments inside
    quoted strings or within multi-character operators like ``>=``.
    """
    import re as _re

    # Replace one-or-more whitespace characters between tokens with /**/.
    # This covers: "' OR 1=1" → "'/**/OR/**/1=1"
    return _re.sub(r"\s+", "/**/", payload)


def apply(encoding: str, payload: str) -> str:
    """Dispatch to the right encoder. Unknown encoding → raises ValueError so
    a misconfigured CLI flag fails loudly instead of silently scanning
    unencoded."""
    if encoding == ENCODING_NONE:
        return payload
    if encoding == ENCODING_URL:
        return url_encode(payload)
    if encoding == ENCODING_DOUBLE_URL:
        return double_url_encode(payload)
    if encoding == ENCODING_BASE64:
        return base64_encode(payload)
    if encoding == ENCODING_SQL_COMMENT:
        return sql_comment_encode(payload)
    raise ValueError(f"Unknown obfuscation encoding: {encoding!r}")
