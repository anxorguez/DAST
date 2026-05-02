"""Unit tests for the CLI entry point.

These tests focus on the output-directory resolution logic and the
debug-log relocation that runs when a scan aborts. They do not exercise
the full Click command (no scan is performed); the goal is to lock down
the contract that:

* The directory under ``reports/`` is computed but NOT created at import
  time or when the user passes ``--help``.
* ``--output`` (via ``settings.scan_name``) maps to a literal directory
  name / path, not to the base directory.
* A failed scan's ``scan.log`` is moved to ``reports/debug/<basename>/``.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from src.core.config import Settings
from src.main import (
    _format_cli_command,
    _make_scan_id,
    _move_log_to_debug,
    _resolve_scan_dir,
)

# ---------------------------------------------------------------------------
# _make_scan_id
# ---------------------------------------------------------------------------


def test_make_scan_id_format() -> None:
    """Scan IDs are ``YYYYMMDD_HHMMSS_<8 hex>``."""
    scan_id = _make_scan_id()
    assert re.match(r"^\d{8}_\d{6}_[0-9a-f]{8}$", scan_id), scan_id


def test_make_scan_id_unique() -> None:
    ids = {_make_scan_id() for _ in range(50)}
    # Random component is 4 bytes; 50 IDs should never collide.
    assert len(ids) == 50


# ---------------------------------------------------------------------------
# _resolve_scan_dir
# ---------------------------------------------------------------------------


def _settings(output_dir: str, scan_name: str | None = None) -> Settings:
    return Settings(
        target_url="http://example.invalid",
        output_dir=output_dir,
        scan_name=scan_name,
    )


def test_resolve_scan_dir_default_uses_random_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCAN_DIR", raising=False)
    base = Path("/tmp/reports")
    settings = _settings(str(base))
    result = _resolve_scan_dir(settings)
    assert result.parent == base
    assert re.match(r"^\d{8}_\d{6}_[0-9a-f]{8}$", result.name)
    # Crucially: nothing on disk yet.
    assert not result.exists()


def test_resolve_scan_dir_with_plain_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """``--output foo`` → ``<base>/foo``."""
    monkeypatch.delenv("SCAN_DIR", raising=False)
    settings = _settings("/tmp/reports", scan_name="smoke_test_express")
    assert _resolve_scan_dir(settings) == Path("/tmp/reports") / "smoke_test_express"


def test_resolve_scan_dir_with_relative_subpath(monkeypatch: pytest.MonkeyPatch) -> None:
    """``--output runs/foo`` → ``<base>/runs/foo``."""
    monkeypatch.delenv("SCAN_DIR", raising=False)
    settings = _settings("/tmp/reports", scan_name="runs/smoke1")
    assert _resolve_scan_dir(settings) == Path("/tmp/reports") / "runs" / "smoke1"


def test_resolve_scan_dir_with_absolute_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Absolute ``--output`` overrides the base entirely."""
    monkeypatch.delenv("SCAN_DIR", raising=False)
    if sys.platform == "win32":
        absolute = "C:/tmp/scan1"
    else:
        absolute = "/tmp/scan1"
    settings = _settings("/tmp/reports", scan_name=absolute)
    result = _resolve_scan_dir(settings)
    assert result.is_absolute()
    assert result == Path(absolute)


def test_resolve_scan_dir_scan_dir_env_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    """``SCAN_DIR`` set by the entrypoint takes precedence over Settings."""
    monkeypatch.setenv("SCAN_DIR", "/tmp/from-entrypoint/abc")
    settings = _settings("/tmp/reports", scan_name="ignored_when_env_present")
    assert _resolve_scan_dir(settings) == Path("/tmp/from-entrypoint/abc")


# ---------------------------------------------------------------------------
# _move_log_to_debug
# ---------------------------------------------------------------------------


def test_move_log_to_debug_relocates_log(tmp_path: Path) -> None:
    """Failed scans must surface their log under ``reports/debug/<id>/``."""
    base = tmp_path / "reports"
    scan_dir = base / "failed_scan"
    scan_dir.mkdir(parents=True)
    log = scan_dir / "scan.log"
    log.write_text("log content", encoding="utf-8")

    new_path = _move_log_to_debug(scan_dir, base)

    assert new_path is not None
    assert new_path == base / "debug" / "failed_scan" / "scan.log"
    assert new_path.exists()
    assert new_path.read_text(encoding="utf-8") == "log content"
    # Original scan_dir should be cleaned up — failed scans must NOT leave
    # an empty directory next to successful ones in reports/.
    assert not scan_dir.exists()


def test_move_log_to_debug_keeps_non_log_files(tmp_path: Path) -> None:
    """If the scan_dir contains anything besides scan.log, leave it alone
    after moving the log so the user can inspect partial state."""
    base = tmp_path / "reports"
    scan_dir = base / "partial"
    scan_dir.mkdir(parents=True)
    (scan_dir / "scan.log").write_text("x", encoding="utf-8")
    (scan_dir / "partial.json").write_text("{}", encoding="utf-8")

    _move_log_to_debug(scan_dir, base)

    # Log moved, partial artefact still in place.
    assert (base / "debug" / "partial" / "scan.log").exists()
    assert scan_dir.exists()
    assert (scan_dir / "partial.json").exists()


def test_move_log_to_debug_no_log_cleans_dir(tmp_path: Path) -> None:
    """Failure before the logger started leaves no log; the empty
    scan_dir must still be removed."""
    base = tmp_path / "reports"
    scan_dir = base / "no_log_yet"
    scan_dir.mkdir(parents=True)

    result = _move_log_to_debug(scan_dir, base)

    assert result is None
    assert not scan_dir.exists()
    assert not (base / "debug").exists()


# ---------------------------------------------------------------------------
# _format_cli_command
# ---------------------------------------------------------------------------


def test_scanner_vector_timeout_cli_flag_overrides_default() -> None:
    """``--scanner-vector-timeout`` propagates into ``Settings``.

    Lock the wiring so the per-vector wall clock is reachable from the CLI
    without a config file edit (regression for the analysis where 120 s
    was burned by time-based payloads on /sqli/[id]).
    """
    from click.testing import CliRunner

    from src.main import main

    captured: dict[str, object] = {}

    def _fake_run(self: object) -> object:
        captured["scanner_vector_timeout_seconds"] = self._settings.scanner_vector_timeout_seconds  # type: ignore[attr-defined]
        # Force exit early so the test doesn't try to spin up a real scan.
        raise SystemExit(0)

    runner = CliRunner()
    with patch("src.pipeline.Pipeline.run", new=_fake_run):
        runner.invoke(
            main,
            [
                "--url",
                "http://localhost",
                "--scanner-vector-timeout",
                "37",
                "--max-pages",
                "1",
                "--depth",
                "0",
            ],
            catch_exceptions=False,
        )

    assert captured.get("scanner_vector_timeout_seconds") == 37


def test_format_cli_command_round_trip() -> None:
    """The CLI string is reproducible from sys.argv via shlex.quote."""
    fake_argv = [
        "python",
        "-m",
        "src.main",
        "--url",
        "http://dvwa",
        "--output",
        "smoke test",  # space → must be quoted
    ]
    with patch.object(sys, "argv", fake_argv):
        result = _format_cli_command()

    # shlex.split is the inverse of join-of-shlex.quote on POSIX shells, so
    # the round trip should give back the original list.
    if os.name == "posix":
        assert shlex.split(result) == fake_argv
    # The space-containing argument must be quoted somehow (single quotes,
    # double quotes, or escaped) — never bare.
    assert "smoke test" not in result.replace("'smoke test'", "")
