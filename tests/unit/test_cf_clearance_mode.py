"""Unit tests for the tri-valued ``cf_clearance_mode`` setting.

The flag was a boolean (``cf_clearance_bridge_enabled``); the post-v5 sprint
turned it into three explicit modes:

* ``off``       — no cookie or User-Agent propagation; the fuzzer has no
  session against a cf-protected target and gets 403 on every request.
* ``propagate`` — cookies + UA propagated, no reactive refresh.
* ``refresh``   — propagation + Playwright relaunch on
  ``X-Cf-Sim-Challenge: expired/missing``.

These tests lock the wiring between ``Settings.cf_clearance_mode`` and the
``Fuzzer`` instance constructed in :class:`Pipeline.run`, plus the validator
on the new field.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from src.core.config import Settings
from src.pipeline import Pipeline


def _settings(mode: str) -> Settings:
    return Settings(
        target_url="http://dvwa-cf",
        output_dir="/tmp/reports",
        cf_clearance_mode=mode,
        max_depth=1,
        max_pages=1,
        max_payloads_per_vector=1,
        payload_types="sqli",
    )


# ---------------------------------------------------------------------------
# Settings.cf_clearance_mode validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["off", "propagate", "refresh"])
def test_cf_clearance_mode_accepts_valid_values(mode: str) -> None:
    settings = Settings(target_url="http://example.invalid", cf_clearance_mode=mode)
    assert settings.cf_clearance_mode == mode


def test_cf_clearance_mode_normalises_case_and_whitespace() -> None:
    settings = Settings(target_url="http://example.invalid", cf_clearance_mode="  REFRESH  ")
    assert settings.cf_clearance_mode == "refresh"


def test_cf_clearance_mode_rejects_unknown_value() -> None:
    with pytest.raises(ValueError, match="cf_clearance_mode"):
        Settings(target_url="http://example.invalid", cf_clearance_mode="bridge")


def test_cf_clearance_mode_defaults_to_off() -> None:
    settings = Settings(target_url="http://example.invalid")
    assert settings.cf_clearance_mode == "off"


# ---------------------------------------------------------------------------
# Pipeline → Fuzzer wiring
# ---------------------------------------------------------------------------


_FAKE_COOKIES: list[dict[str, Any]] = [{"name": "cf_clearance", "value": "x"}]
_FAKE_UA = "Mozilla/5.0 fake-ua"


class _FakeCrawler:
    """Stand-in for the real Crawler with deterministic session output."""

    session_cookies: list[dict[str, Any]] = _FAKE_COOKIES
    session_user_agent: str | None = _FAKE_UA

    def __init__(self, _settings: Settings) -> None:
        pass

    async def crawl(self) -> list[Any]:
        return []

    async def refresh_session_async(self) -> dict[str, Any]:
        return {"cookies": self.session_cookies, "user_agent": self.session_user_agent}

    crawl_stats: Any = None


class _PipelineExit(SystemExit):
    """Sentinel raised by the fake Fuzzer so the pipeline aborts cleanly."""


def _make_fake_fuzzer(captured: dict[str, Any]) -> Any:
    """Return a Fuzzer stand-in that records the constructor args and aborts."""

    class _FakeFuzzer:
        def __init__(
            self,
            settings: Settings,
            session_cookies: list[dict[str, Any]] | None = None,
            rate_limiter: Any = None,
            session_user_agent: str | None = None,
            cf_clearance_refresh_callback: Any = None,
        ) -> None:
            captured["session_cookies"] = session_cookies
            captured["session_user_agent"] = session_user_agent
            captured["refresh_cb"] = cf_clearance_refresh_callback
            raise _PipelineExit(0)

    return _FakeFuzzer


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "expected_cookies", "expected_ua", "expects_refresh"),
    [
        ("off", [], None, False),
        ("propagate", _FAKE_COOKIES, _FAKE_UA, False),
        ("refresh", _FAKE_COOKIES, _FAKE_UA, True),
    ],
)
async def test_pipeline_wires_fuzzer_based_on_cf_clearance_mode(
    tmp_path: Path,
    mode: str,
    expected_cookies: list[dict[str, Any]],
    expected_ua: str | None,
    expects_refresh: bool,
) -> None:
    captured: dict[str, Any] = {}

    pipeline = Pipeline(_settings(mode), tmp_path)
    with (
        patch("src.pipeline.Crawler", new=_FakeCrawler),
        patch("src.pipeline.VectorAnalyzer") as MockAnalyzer,
        patch("src.pipeline.Fuzzer", new=_make_fake_fuzzer(captured)),
    ):
        MockAnalyzer.return_value.analyze.return_value = []
        with pytest.raises(_PipelineExit):
            await pipeline.run()

    assert captured["session_cookies"] == expected_cookies
    assert captured["session_user_agent"] == expected_ua
    if expects_refresh:
        assert captured["refresh_cb"] is not None
    else:
        assert captured["refresh_cb"] is None


# ---------------------------------------------------------------------------
# CLI propagation
# ---------------------------------------------------------------------------


def test_cli_cf_clearance_mode_flag_propagates_to_settings() -> None:
    """``--cf-clearance-mode refresh`` ends up in ``Settings.cf_clearance_mode``."""
    from click.testing import CliRunner

    from src.main import main

    captured: dict[str, object] = {}

    def _fake_run(self: object) -> object:
        captured["mode"] = self._settings.cf_clearance_mode  # type: ignore[attr-defined]
        raise SystemExit(0)

    runner = CliRunner()
    with patch("src.pipeline.Pipeline.run", new=_fake_run):
        runner.invoke(
            main,
            [
                "--url",
                "http://localhost",
                "--cf-clearance-mode",
                "refresh",
                "--max-pages",
                "1",
                "--depth",
                "1",
            ],
            catch_exceptions=False,
        )

    assert captured.get("mode") == "refresh"


def test_cli_cf_clearance_mode_rejects_invalid_value() -> None:
    from click.testing import CliRunner

    from src.main import main

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["--url", "http://localhost", "--cf-clearance-mode", "bogus"],
    )
    # Click's Choice validation aborts before Pydantic; exit code is non-zero.
    assert result.exit_code != 0
