"""Unsafe Deserialization scanner: exception-based detection."""

from __future__ import annotations

import base64
import re

from loguru import logger

from src.analysis.models import Confidence, RawFinding
from src.core.config import Settings
from src.core.http_client import HTTPClient
from src.vectors.models import AttackVector, VulnType

from .base_scanner import BaseScanner

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

# Exception messages emitted when malformed serialized data is processed.
_DESER_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # Java
        r"java\.io\.InvalidClassException",
        r"java\.io\.StreamCorruptedException",
        r"java\.lang\.ClassNotFoundException",
        r"java\.io\.ObjectStreamException",
        r"NotSerializableException",
        r"InvalidObjectException",
        r"readObject",
        # PHP
        r"unserialize\(\).*error",
        r"unserialize\(\): Error at offset",
        r"unserialization failed",
        r"__wakeup\(\)",
        r"__destruct\(\)",
        # Python
        r"pickle\.UnpicklingError",
        r"_pickle\.UnpicklingError",
        r"could not find MARK",
        r"invalid load key",
        r"struct\.error.*unpack",
        # .NET
        r"SerializationException",
        r"BinaryFormatter",
        r"System\.Runtime\.Serialization",
        r"invalid type code",
        # YAML (SnakeYAML)
        r"cannot construct.*java\.",
        r"SnakeYAML",
        r"org\.yaml\.snakeyaml",
        # Generic
        r"deserialization.*failed",
        r"deserializ.*error",
        r"malformed.*serializ",
    ]
]

# Patterns that suggest the field might contain serialized data.
_SERIALIZED_VALUE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^rO0AB"),  # Java: base64(0xAC 0xED 0x00 0x05)
    re.compile(r"^AAEAAAD"),  # .NET BinaryFormatter base64 header
    re.compile(r"^O:\d+:"),  # PHP object serialization
    re.compile(r"^a:\d+:\{"),  # PHP array serialization
    re.compile(r"^s:\d+:"),  # PHP string serialization
    re.compile(r"^\x80[\x02-\x05]"),  # Python pickle PROTO opcode
    re.compile(r"^gAS"),  # Python pickle protocol 4+ base64
]


def _looks_serialized(value: str) -> bool:
    """Return True if *value* resembles serialized data."""
    # Check raw value patterns.
    for pat in _SERIALIZED_VALUE_PATTERNS:
        if pat.search(value):
            return True
    # Try base64 decode and check for magic bytes.
    try:
        decoded = base64.b64decode(value + "==")
        if decoded[:2] == b"\xac\xed":  # Java serialization magic
            return True
        if decoded[:4] == b"\x00\x01\x00\x00":  # .NET BinaryFormatter
            return True
    except Exception:
        pass
    return False


class DeserializationScanner(BaseScanner):
    """Detects unsafe deserialization by sending malformed serialized objects.

    A finding is emitted when the server returns a deserialization exception
    (CONFIRMED) or a 500-error that correlates with a serialization payload
    (LIKELY).
    """

    VULN_TYPE = VulnType.DESERIALIZATION

    def __init__(self, settings: Settings, http_client: HTTPClient) -> None:
        super().__init__(settings, http_client)

    async def _detect(self, vector: AttackVector, payload: str) -> RawFinding | None:
        """Send a malformed serialized payload and inspect the response."""
        try:
            response, elapsed = await self._send(vector, payload)
            body = response.text

            # Strategy 1: deserialization exception visible in response body.
            for pattern in _DESER_ERROR_PATTERNS:
                match = pattern.search(body)
                if match:
                    evidence = (
                        f"Deserialization error '{match.group(0)}' in response "
                        f"(HTTP {response.status_code}) — unsafe deserialization "
                        f"detected."
                    )
                    logger.debug(
                        "Deserialization confirmed: {url} [{field}]",
                        url=vector.target_url,
                        field=vector.field_name,
                    )
                    return self._make_finding(
                        vector,
                        payload,
                        response,
                        elapsed,
                        Confidence.CONFIRMED,
                        evidence,
                    )

            # Strategy 2: HTTP 500 with a serialization-style payload is suspicious.
            if response.status_code == 500 and _looks_serialized(payload):
                evidence = (
                    f"HTTP 500 returned for malformed serialized payload "
                    f"(possible unsafe deserialization). "
                    f"Payload prefix: {payload[:40]}"
                )
                logger.debug(
                    "Deserialization likely (500): {url} [{field}]",
                    url=vector.target_url,
                    field=vector.field_name,
                )
                return self._make_finding(
                    vector,
                    payload,
                    response,
                    elapsed,
                    Confidence.LIKELY,
                    evidence,
                )

        except Exception as exc:
            logger.debug(
                "DeserializationScanner error on {url} [{field}]: {err}",
                url=vector.target_url,
                field=vector.field_name,
                err=exc,
            )

        return None
