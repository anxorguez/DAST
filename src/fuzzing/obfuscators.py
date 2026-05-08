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

ALL_ENCODINGS: Final[tuple[str, ...]] = (
    ENCODING_NONE,
    ENCODING_URL,
    ENCODING_DOUBLE_URL,
    ENCODING_BASE64,
)


def url_encode(payload: str) -> str:
    """Single percent-encoding. Caller MUST send the result verbatim, bypassing
    httpx auto-encoding, otherwise the ``%`` characters get re-encoded and the
    wire form becomes double-encoded by accident."""
    # safe="" so reserved chars (=, &, /, etc.) are encoded too.
    return quote(payload, safe="")


def double_url_encode(payload: str) -> str:
    """Apply percent-encoding twice. Result is intended to be passed to httpx
    via the normal params/data path: httpx will percent-encode the leading
    ``%`` characters, producing ``%25xx`` on the wire."""
    return quote(quote(payload, safe=""), safe="")


def base64_encode(payload: str) -> str:
    """UTF-8 → base64 (standard alphabet, with padding)."""
    return _b64.b64encode(payload.encode("utf-8")).decode("ascii")


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
    raise ValueError(f"Unknown obfuscation encoding: {encoding!r}")
