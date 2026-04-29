"""Application configuration via Pydantic Settings v2.

Settings are loaded from environment variables (and a local ``.env`` file).
Tuning parameters that used to live in YAML scan profiles are now exposed
directly as CLI flags or environment variables.
"""

from __future__ import annotations

from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All runtime configuration for the DAST framework."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Target -------------------------------------------------------
    target_url: str = ""

    # --- Output -------------------------------------------------------
    # ``output_dir`` is the base directory under which scan folders are
    # created (the *root* of ``reports/``).  ``scan_name`` is the name (or
    # path) of the per-scan subdirectory; if ``None``, a timestamp+random
    # ID is generated at runtime.  Splitting the two concerns means that
    # ``--output`` can carry the *name* the user wants while the base stays
    # configurable via ``--output-base`` / ``OUTPUT_DIR``.
    output_dir: str = "/app/reports"
    scan_name: str | None = None
    log_level: str = "INFO"

    # --- Crawler ------------------------------------------------------
    max_depth: int = 3
    max_pages: int = 100
    request_timeout: int = 30
    concurrent_pages: int = 5

    # --- Authentication (optional) ------------------------------------
    auth_enabled: bool = False
    auth_url: str = ""
    auth_username: str = ""
    auth_password: str = ""
    auth_username_field: str = "username"
    auth_password_field: str = "password"
    auth_success_url: str = ""

    # --- Fuzzing ------------------------------------------------------
    payload_types: str = "sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect"
    max_payloads_per_vector: int = 50
    concurrent_vectors: int = 5  # Max vectors scanned in parallel
    concurrent_payloads: int = 10  # Max payloads tested in parallel per scanner
    requests_per_second: int = 0  # Rate limit (0 = unlimited)
    # Total HTTP attempts per request inside scanners.  1 = no retry, which is
    # the right default for fuzzing because retries multiply the cost of a
    # toxic payload (3 × request_timeout) without adding signal.  Raise to 3
    # only on flaky networks where transient errors are common.
    scanner_http_retries: int = 1
    # Hard wall-clock cap on the time a single (vector × scanner) pair can
    # spend in :meth:`Fuzzer._fuzz_vector`.  Prevents one stuck endpoint from
    # blocking the whole fuzz phase indefinitely.
    scanner_vector_timeout_seconds: int = 120

    # --- Database -----------------------------------------------------
    db_path: str = ""

    # --- DVWA (integration tests) ------------------------------------
    dvwa_security_level: str = "low"
    dvwa_username: str = "admin"
    dvwa_password: str = "password"

    # -----------------------------------------------------------------
    @field_validator("log_level", mode="before")
    @classmethod
    def _validate_log_level(cls, v: object) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        s = str(v).upper()
        if s not in valid:
            raise ValueError(f"log_level must be one of {valid}, got '{v}'")
        return s

    # -----------------------------------------------------------------
    @property
    def payload_types_list(self) -> list[str]:
        """Return the payload_types field as a list of lowercase strings."""
        return [t.strip().lower() for t in self.payload_types.split(",") if t.strip()]


# ---------------------------------------------------------------------------
# Settings factory
# ---------------------------------------------------------------------------


def get_settings(**overrides: Any) -> Settings:
    """Build a Settings instance, applying explicit overrides on top of env/defaults.

    Priority (highest wins): overrides > environment variables > defaults.
    """
    merged = {k: v for k, v in overrides.items() if v is not None}
    return Settings(**merged)
