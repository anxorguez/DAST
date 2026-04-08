"""Application configuration via Pydantic Settings v2.

Settings are loaded from environment variables and optionally from a YAML
profile file. Environment variables always take precedence over profile values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
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
    scan_profile: str = "default"

    # --- Output -------------------------------------------------------
    output_dir: str = "/app/reports"
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
    concurrent_vectors: int = 5    # Max vectors scanned in parallel
    concurrent_payloads: int = 10  # Max payloads tested in parallel per scanner
    requests_per_second: int = 0   # Rate limit (0 = unlimited)

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

    @field_validator("scan_profile", mode="before")
    @classmethod
    def _validate_profile(cls, v: object) -> str:
        valid = {"default", "aggressive", "stealth"}
        s = str(v).lower()
        if s not in valid:
            raise ValueError(f"scan_profile must be one of {valid}, got '{v}'")
        return s

    # -----------------------------------------------------------------
    @property
    def payload_types_list(self) -> list[str]:
        """Return the payload_types field as a list of lowercase strings."""
        return [t.strip().lower() for t in self.payload_types.split(",") if t.strip()]


# ---------------------------------------------------------------------------
# Profile loading helpers
# ---------------------------------------------------------------------------

_PROFILES_DIR = Path(__file__).parent.parent.parent / "config"


def _load_profile(profile_name: str) -> dict[str, Any]:
    """Load a YAML profile file and return its contents as a dict."""
    profile_path = _PROFILES_DIR / f"{profile_name}.yaml"
    if not profile_path.exists():
        return {}
    with profile_path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data if isinstance(data, dict) else {}


def get_settings(profile: str | None = None, **overrides: Any) -> Settings:
    """Build a Settings instance, merging profile defaults and explicit overrides.

    Priority (highest wins): overrides > environment variables > profile YAML > defaults.
    """
    profile_data: dict[str, Any] = {}
    if profile:
        profile_data = _load_profile(profile)

    # Merge: start from profile data as base, then apply explicit overrides.
    # Pydantic Settings will still read env vars on top of everything.
    merged = {**profile_data, **{k: v for k, v in overrides.items() if v is not None}}
    return Settings(**merged)
