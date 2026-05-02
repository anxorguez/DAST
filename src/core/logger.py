"""Centralised Loguru configuration for the DAST framework."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from loguru import Logger

_LOG_FORMAT = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | {name}:{line} | {message}"


def setup_logger(log_level: str = "INFO", log_file: Path | None = None) -> None:
    """Configure Loguru with a console handler and an optional file handler.

    This function is idempotent: it removes all existing handlers before
    adding new ones, so it is safe to call multiple times (e.g. in tests).

    Args:
        log_level: Logging threshold. One of DEBUG, INFO, WARNING, ERROR, CRITICAL.
        log_file: Optional path to a file where logs are written. The file is
            rotated at 50 MB and compressed to zip.
    """
    logger.remove()

    logger.add(
        sys.stderr,
        format=_LOG_FORMAT,
        level=log_level.upper(),
        colorize=True,
        enqueue=False,
    )

    if log_file is not None:
        # Per-scan log file: no rotation, no compression — each scan has its
        # own ``scan.log`` under ``reports/outputs/<scan>/`` so size-based
        # rotation only adds failure modes (the previously rotated chunks
        # were getting lost mid-scan during multi-hour runs, leaving the
        # last 18 minutes of a 28-minute stealth scan absent from the file).
        # ``enqueue=True`` routes records through a background worker that
        # flushes after every write, so the tail of long-running scans is
        # always on disk by the time the process exits.
        logger.add(
            str(log_file),
            format=_LOG_FORMAT,
            level=log_level.upper(),
            encoding="utf-8",
            enqueue=True,
        )


def get_logger(name: str) -> Logger:
    """Return a logger bound to a specific module name.

    Usage::

        log = get_logger(__name__)
        log.info("message")
    """
    return logger.bind(name=name)
