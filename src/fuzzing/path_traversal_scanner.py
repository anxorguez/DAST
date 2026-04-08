"""Path Traversal (LFI/Directory Traversal) scanner."""

from __future__ import annotations

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

# Content patterns that only appear inside sensitive system files.
_FILE_CONTENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # /etc/passwd
        r"root:x:\d+:\d+:",
        r"daemon:x:\d+:\d+:",
        r"nobody:x:\d+:\d+:",
        r"/bin/(sh|bash|dash|nologin)",
        # /etc/hosts
        r"127\.0\.0\.1\s+localhost",
        r"::1\s+localhost",
        # Windows win.ini / boot.ini / system.ini
        r"\[boot loader\]",
        r"\[fonts\]",
        r"\[extensions\]",
        r"\[mci extensions\]",
        r"operating systems",
        r"WINDOWS\s*=",
        # Other indicators
        r"\[php\]",           # php.ini
        r"extension_dir\s*=",  # php.ini
    ]
]

# Error patterns that indicate a traversal attempt was partially processed.
_TRAVERSAL_ERROR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"failed to open stream",
        r"no such file or directory",
        r"file not found",
        r"include_path",
        r"open_basedir restriction",
        r"Permission denied",
        r"cannot open.*for reading",
        r"Invalid file.*path",
        r"directory listing denied",
    ]
]

# Field names that commonly accept file paths and are therefore high-value targets.
_PATH_HINT_NAMES: frozenset[str] = frozenset(
    {
        "file", "filename", "path", "document", "template", "page",
        "include", "dir", "folder", "src", "download", "read", "load",
        "resource", "location", "url", "link", "name", "view",
    }
)


class PathTraversalScanner(BaseScanner):
    """Detects path traversal (LFI/directory traversal) by analysing file content leakage.

    Only runs against vectors whose field names suggest file/path context.
    """

    VULN_TYPE = VulnType.PATH_TRAVERSAL

    def __init__(self, settings: Settings, http_client: HTTPClient) -> None:
        super().__init__(settings, http_client)

    async def _detect(
        self, vector: AttackVector, payload: str
    ) -> RawFinding | None:
        """Inject a traversal sequence and check if system file content is returned."""
        try:
            response, elapsed = await self._send(vector, payload)
            body = response.text

            # Strategy 1: actual file content visible in response.
            for pattern in _FILE_CONTENT_PATTERNS:
                match = pattern.search(body)
                if match:
                    evidence = (
                        f"Path Traversal: system file content '{match.group(0)}' "
                        f"found in response (HTTP {response.status_code})."
                    )
                    logger.debug(
                        "PathTraversal confirmed: {url} [{field}]",
                        url=vector.target_url,
                        field=vector.field_name,
                    )
                    return self._make_finding(
                        vector, payload, response, elapsed,
                        Confidence.CONFIRMED, evidence,
                    )

            # Strategy 2: file-access error — traversal reached the filesystem.
            for pattern in _TRAVERSAL_ERROR_PATTERNS:
                match = pattern.search(body)
                if match:
                    evidence = (
                        f"Path Traversal: filesystem error '{match.group(0)}' "
                        f"suggests traversal was processed by the server "
                        f"(HTTP {response.status_code})."
                    )
                    logger.debug(
                        "PathTraversal likely: {url} [{field}] error='{e}'",
                        url=vector.target_url,
                        field=vector.field_name,
                        e=match.group(0),
                    )
                    return self._make_finding(
                        vector, payload, response, elapsed,
                        Confidence.LIKELY, evidence,
                    )

        except Exception as exc:
            logger.debug(
                "PathTraversalScanner error on {url} [{field}]: {err}",
                url=vector.target_url,
                field=vector.field_name,
                err=exc,
            )

        return None
