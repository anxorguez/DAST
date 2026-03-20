"""Centralised Loguru configuration for the DAST framework."""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

_LOG_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | {name}:{line} | {message}"
)


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
        logger.add(
            str(log_file),
            format=_LOG_FORMAT,
            level=log_level.upper(),
            rotation="50 MB",
            compression="zip",
            encoding="utf-8",
            enqueue=False,
        )


def get_logger(name: str) -> "logger":  # type: ignore[name-defined]
    """Return a logger bound to a specific module name.

    Usage::

        log = get_logger(__name__)
        log.info("message")
    """
    return logger.bind(name=name)
