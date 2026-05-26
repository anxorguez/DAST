"""Application configuration via Pydantic Settings v2.

Settings are loaded from environment variables (and a local ``.env`` file).
Tuning parameters that used to live in YAML scan profiles are now exposed
directly as CLI flags or environment variables.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator
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
    # created.  Two subtrees live below it:
    #   * ``<output_dir>/<scan_name>/`` — successful scans.
    #   * ``<output_dir>/debug/<scan_name>/`` — aborted/failed scans (only
    #     ``scan.log`` is preserved so the failure can be diagnosed).
    # ``scan_name`` is the name (or path) of the per-scan subdirectory; if
    # ``None``, a timestamp+random ID is generated at runtime.  Splitting
    # the two concerns means that ``--output`` can carry the *name* the
    # user wants while the base stays configurable via ``--output-base`` /
    # ``OUTPUT_DIR``.
    #
    # Default base sits at ``/app/reports/outputs`` (and ``./reports/outputs``
    # in development) so that ``reports/`` itself contains *only*
    # ``outputs/`` and ``docs/``.
    output_dir: str = "/app/reports/outputs"
    scan_name: str | None = None
    log_level: str = "INFO"

    # --- Crawler ------------------------------------------------------
    # Convención: None = "sin tope". requests_per_second mantiene 0 = unlimited
    # por compatibilidad histórica; los cuatro campos de cobertura usan None.
    max_depth: int | None = 3
    max_pages: int | None = 100
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

    # --- Anti-bot / session bridge ------------------------------------
    cf_clearance_bridge_enabled: bool = Field(
        default=False,
        description=(
            "Enable reactive refresh of cf_clearance cookie via Playwright when "
            "an upstream returns X-Cf-Sim-Challenge: expired/missing. The "
            "User-Agent and cookies are propagated from the crawler to the fuzzer "
            "either way; this flag only controls the refresh-on-expiry behaviour."
        ),
    )

    # --- Fuzzing ------------------------------------------------------
    payload_types: str = "sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect"
    # CSV of payload obfuscation encodings to apply.  Each scanner declares which
    # encodings make sense for its vuln class via SUPPORTED_ENCODINGS; the
    # effective list per scanner is the intersection of this setting and that
    # tuple.  An empty intersection falls back to ``"none"`` so the scanner still
    # runs.  Valid values: none, url, double_url, base64.  See
    # src/fuzzing/obfuscators.py for the full catalogue.
    obfuscation: str = "none"
    max_payloads_per_vector: int | None = 50
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
    # blocking the whole fuzz phase indefinitely.  None = no cap.
    scanner_vector_timeout_seconds: int | None = 120

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

    @field_validator("obfuscation", mode="before")
    @classmethod
    def _validate_obfuscation(cls, v: object) -> str:
        from src.fuzzing.obfuscators import ALL_ENCODINGS

        s = str(v).lower()
        tokens = [t.strip() for t in s.split(",") if t.strip()]
        if not tokens:
            return "none"
        bad = [t for t in tokens if t not in ALL_ENCODINGS]
        if bad:
            raise ValueError(
                f"obfuscation contains unknown encoding(s) {bad}; valid: {sorted(ALL_ENCODINGS)}"
            )
        return ",".join(tokens)

    # -----------------------------------------------------------------
    @property
    def payload_types_list(self) -> list[str]:
        """Return the payload_types field as a list of lowercase strings."""
        return [t.strip().lower() for t in self.payload_types.split(",") if t.strip()]

    @property
    def obfuscation_list(self) -> list[str]:
        """Return the obfuscation field as a list of lowercase strings."""
        return [t.strip().lower() for t in self.obfuscation.split(",") if t.strip()]


# ---------------------------------------------------------------------------
# Settings factory
# ---------------------------------------------------------------------------


def get_settings(**overrides: Any) -> Settings:
    """Build a Settings instance, applying explicit overrides on top of env/defaults.

    Priority (highest wins): overrides > environment variables > defaults.
    ``None`` is a meaningful override for coverage fields (means "unlimited");
    callers are responsible for only including keys they actually want to set.
    """
    return Settings(**overrides)
