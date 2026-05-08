"""CLI entry point for the DAST framework.

Usage:
    python -m src.main --url http://dvwa
    python -m src.main --url http://target \\
        --concurrent-vectors 5 --concurrent-payloads 10 --requests-per-second 0 \\
        --depth 3 --max-pages 100 --max-payloads-per-vector 50 \\
        --payload-types sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect \\
        --request-timeout 30

The flags split into two groups:

* Velocidad / huella — control how many requests run in parallel and how fast:
  ``--concurrent-vectors``, ``--concurrent-payloads``, ``--requests-per-second``.
* Cobertura / alcance — control which parts of the target are explored and
  how thoroughly: ``--depth``, ``--max-pages``, ``--max-payloads-per-vector``,
  ``--payload-types``, ``--request-timeout``.

Output directory rules:

* No scan directory is created until the scan actually starts. ``--help``,
  ``--version`` or argument-validation failures leave ``reports/`` untouched.
* A successful scan writes its artefacts under ``reports/<scan_id>/`` (or the
  name passed via ``--output``).
* A scan that aborts before completion is persisted under
  ``reports/debug/<scan_id>/scan.log`` — only the log is kept.
"""

from __future__ import annotations

import asyncio
import binascii
import os
import shlex
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import click
from loguru import logger

from src.core.config import Settings, get_settings
from src.core.exceptions import DASTError
from src.core.logger import setup_logger
from src.pipeline import Pipeline

# Fields excluded from the effective-settings dump for safety/relevance.
_SETTINGS_REDACT: frozenset[str] = frozenset({"auth_password", "dvwa_password", "db_path"})


def _make_scan_id() -> str:
    """Generate a unique scan ID: YYYYMMDD_HHMMSS_<8 random hex chars>."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    rand_hex = binascii.hexlify(os.urandom(4)).decode("ascii")
    return f"{timestamp}_{rand_hex}"


def _safe_dump(settings: Settings) -> dict[str, Any]:
    """Return Settings as a dict with sensitive fields removed."""
    return settings.model_dump(exclude=set(_SETTINGS_REDACT))


def _resolve_scan_dir(settings: Settings) -> Path:
    """Compute the planned scan directory without creating it on disk.

    Priority:
        1. ``SCAN_DIR`` environment variable (set by ``entrypoint.sh``) wins,
           because the shell already resolved the user's intent (including
           parsing ``--output``).
        2. ``settings.scan_name`` — relative paths are joined to
           ``output_dir``; absolute paths are used as-is.
        3. Fallback to a timestamp+random ID under ``output_dir``.
    """
    scan_dir_env = os.environ.get("SCAN_DIR", "")
    if scan_dir_env:
        return Path(scan_dir_env)
    if settings.scan_name:
        candidate = Path(settings.scan_name)
        return candidate if candidate.is_absolute() else Path(settings.output_dir) / candidate
    return Path(settings.output_dir) / _make_scan_id()


def _format_cli_command() -> str:
    """Reconstruct the original CLI invocation as a shell-quoted string.

    Used so the report can include the exact command that produced it. We
    rebuild from ``sys.argv`` rather than from Click's parsed values to keep
    the surface form (flag aliases, ``=`` syntax, order) exactly as the user
    typed it.
    """
    return " ".join(shlex.quote(arg) for arg in sys.argv)


def _move_log_to_debug(scan_dir: Path, output_base: Path) -> Path | None:
    """Relocate the scan log to ``reports/debug/<basename>/scan.log``.

    Removes ``scan_dir`` afterwards if it is left empty so a failed scan
    leaves no orphan directory next to successful ones.

    Returns the new log path, or ``None`` if no log existed to move.
    """
    # Stop loguru from holding the file handle so the move is safe on Windows.
    logger.remove()

    src = scan_dir / "scan.log"
    if not src.exists():
        # Nothing to persist — still try to clean up an empty scan_dir.
        try:
            scan_dir.rmdir()
        except OSError:
            pass
        return None

    debug_root = output_base / "debug" / scan_dir.name
    debug_root.mkdir(parents=True, exist_ok=True)
    dst = debug_root / "scan.log"
    shutil.move(str(src), str(dst))

    try:
        scan_dir.rmdir()
    except OSError:
        # scan_dir still has other files (rotation artefacts, etc.); leave it.
        pass

    return dst


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--url",
    required=True,
    envvar="TARGET_URL",
    help="Target URL to scan (e.g. http://dvwa).",
)
# --- Velocidad / huella ------------------------------------------------------
@click.option(
    "--concurrent-vectors",
    "concurrent_vectors",
    default=5,
    show_default=True,
    type=int,
    envvar="CONCURRENT_VECTORS",
    help=(
        "[Velocidad] Maximum number of attack vectors fuzzed in parallel. "
        "Does NOT change what is tested, only how fast."
    ),
)
@click.option(
    "--concurrent-payloads",
    "concurrent_payloads",
    default=10,
    show_default=True,
    type=int,
    envvar="CONCURRENT_PAYLOADS",
    help=(
        "[Velocidad] Maximum number of payloads tested in parallel per scanner. "
        "Does NOT change what is tested, only how fast."
    ),
)
@click.option(
    "--requests-per-second",
    "requests_per_second",
    default=0,
    show_default=True,
    type=int,
    envvar="REQUESTS_PER_SECOND",
    help=(
        "[Velocidad] Global rate limit in requests per second (0 = unlimited). "
        "Applies to ALL scanners and vectors combined."
    ),
)
# --- Cobertura / alcance ----------------------------------------------------
@click.option(
    "--depth",
    "depth",
    default=3,
    show_default=True,
    type=int,
    envvar="MAX_DEPTH",
    help="[Cobertura] Maximum BFS depth followed by the crawler.",
)
@click.option(
    "--max-pages",
    "max_pages",
    default=100,
    show_default=True,
    type=int,
    envvar="MAX_PAGES",
    help=(
        "[Cobertura] Hard cap on pages crawled. Together with --depth, defines the crawler's reach."
    ),
)
@click.option(
    "--max-payloads-per-vector",
    "max_payloads_per_vector",
    default=50,
    show_default=True,
    type=int,
    envvar="MAX_PAYLOADS_PER_VECTOR",
    help=(
        "[Cobertura] Maximum payloads per (vector × scanner). Dominant lever "
        "for cost and intrusiveness."
    ),
)
@click.option(
    "--payload-types",
    "payload_types",
    default="sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect",
    show_default=True,
    type=str,
    envvar="PAYLOAD_TYPES",
    help=(
        "[Cobertura] CSV list of active scanner classes. Valid values: "
        "sqli, xss, cmdi, ssrf, xxe, deserialization, path_traversal, "
        "open_redirect."
    ),
)
@click.option(
    "--obfuscation",
    "obfuscation",
    default="none",
    show_default=True,
    type=str,
    envvar="OBFUSCATION",
    help=(
        "[Cobertura] CSV list of payload obfuscation encodings to apply. "
        "Valid values: none, url, double_url, base64. Each scanner declares "
        "which encodings make sense for its vuln class; the effective set is "
        "the intersection. Multiplies per-vector cost by len(intersection)."
    ),
)
@click.option(
    "--request-timeout",
    "request_timeout",
    default=30,
    show_default=True,
    type=int,
    envvar="REQUEST_TIMEOUT",
    help="[Cobertura] HTTP request timeout in seconds.",
)
@click.option(
    "--scanner-vector-timeout",
    "scanner_vector_timeout",
    default=None,
    type=int,
    envvar="SCANNER_VECTOR_TIMEOUT_SECONDS",
    help=(
        "[Cobertura] Wall-clock cap (seconds) for one scanner against one vector "
        "before its in-flight payloads are cancelled. Lower values keep the run "
        "moving past stuck endpoints; higher values give time-based payloads "
        "(SLEEP/BENCHMARK) room to confirm. Default 120s."
    ),
)
# --- Output / logging --------------------------------------------------------
@click.option(
    "--output",
    default=None,
    envvar="SCAN_NAME",
    help=(
        "Name of the scan output directory under the reports base "
        "(default base: ./reports). Accepts a plain name "
        "('smoke_test_express'), a relative path with subdirs ('runs/smoke1') "
        "or an absolute path. If omitted, a timestamp_random ID is generated. "
        "Re-running with the same name silently overwrites the previous scan."
    ),
)
@click.option(
    "--output-base",
    default=None,
    envvar="OUTPUT_DIR",
    help="Base directory where scan folders live. Defaults to ./reports.",
)
@click.option(
    "--log-level",
    default=None,
    envvar="LOG_LEVEL",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    help="Logging verbosity.",
)
def main(
    url: str,
    concurrent_vectors: int,
    concurrent_payloads: int,
    requests_per_second: int,
    depth: int,
    max_pages: int,
    max_payloads_per_vector: int,
    payload_types: str,
    obfuscation: str,
    request_timeout: int,
    scanner_vector_timeout: int | None,
    output: str | None,
    output_base: str | None,
    log_level: str | None,
) -> None:
    """DAST Framework — automated injection vulnerability scanner."""
    # ------------------------------------------------------------------
    # Build settings (no disk side-effects yet)
    # ------------------------------------------------------------------
    overrides: dict[str, object] = {
        "target_url": url,
        "concurrent_vectors": concurrent_vectors,
        "concurrent_payloads": concurrent_payloads,
        "requests_per_second": requests_per_second,
        "max_depth": depth,
        "max_pages": max_pages,
        "max_payloads_per_vector": max_payloads_per_vector,
        "payload_types": payload_types,
        "obfuscation": obfuscation,
        "request_timeout": request_timeout,
    }
    if scanner_vector_timeout is not None:
        overrides["scanner_vector_timeout_seconds"] = scanner_vector_timeout
    if output:
        overrides["scan_name"] = output
    if output_base:
        overrides["output_dir"] = output_base
    if log_level:
        overrides["log_level"] = log_level

    settings = get_settings(**overrides)

    cli_command = _format_cli_command()

    # ------------------------------------------------------------------
    # Resolve the scan output directory and create it.  Creation is
    # deferred to this point so that commands which never reach main()'s
    # body (``--help``, validation failures) leave ``reports/`` untouched.
    # ------------------------------------------------------------------
    scan_dir = _resolve_scan_dir(settings)
    output_base_path = Path(settings.output_dir)
    reusing_existing = (
        settings.scan_name is not None and scan_dir.exists() and any(scan_dir.iterdir())
    )
    scan_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Configure logging
    # ------------------------------------------------------------------
    setup_logger(log_level=settings.log_level, log_file=scan_dir / "scan.log")

    if reusing_existing:
        logger.info(
            "Reusing existing scan directory: {p} (contents will be overwritten)",
            p=str(scan_dir),
        )

    logger.info(
        "DAST Framework starting | url={u} | cv={cv} | cp={cp} | rps={rps} | "
        "depth={d} | max_pages={mp} | max_payloads_per_vector={mppv} | "
        "payload_types={pt} | obf={obf} | request_timeout={rt} | scan_dir={s}",
        u=url,
        cv=concurrent_vectors,
        cp=concurrent_payloads,
        rps=requests_per_second,
        d=depth,
        mp=max_pages,
        mppv=max_payloads_per_vector,
        pt=payload_types,
        obf=obfuscation,
        rt=request_timeout,
        s=str(scan_dir),
    )
    logger.info("Effective settings: {s}", s=_safe_dump(settings))
    logger.info("CLI command: {c}", c=cli_command)

    # ------------------------------------------------------------------
    # Run pipeline
    # ------------------------------------------------------------------
    pipeline = Pipeline(settings, scan_dir, cli_command=cli_command)

    try:
        report = asyncio.run(pipeline.run())
    except DASTError as exc:
        logger.error("Scan aborted: {e}", e=exc)
        debug_path = _move_log_to_debug(scan_dir, output_base_path)
        if debug_path is not None:
            click.echo(f"Scan failed. Debug log: {debug_path}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        debug_path = _move_log_to_debug(scan_dir, output_base_path)
        if debug_path is not None:
            click.echo(f"Scan interrupted. Debug log: {debug_path}", err=True)
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error: {e}", e=exc)
        debug_path = _move_log_to_debug(scan_dir, output_base_path)
        if debug_path is not None:
            click.echo(f"Scan failed. Debug log: {debug_path}", err=True)
        sys.exit(1)

    # ------------------------------------------------------------------
    # Summary to stdout
    # ------------------------------------------------------------------
    summary = report.summary
    click.echo("")
    click.echo("Scan complete.")
    click.echo(f"  Scan ID    : {report.scan_id}")
    click.echo(f"  Target     : {report.target_url}")
    click.echo(f"  Pages      : {report.pages_crawled}")
    click.echo(f"  Vectors    : {report.vectors_found}")
    click.echo(f"  Findings   : {len(report.findings)}")
    click.echo(
        f"    CRITICAL : {summary.get('critical', 0)}"
        f"  HIGH : {summary.get('high', 0)}"
        f"  MEDIUM : {summary.get('medium', 0)}"
        f"  LOW : {summary.get('low', 0)}"
        f"  INFO : {summary.get('info', 0)}"
    )
    click.echo(f"  Reports    : {scan_dir}")
    click.echo("")

    exit_code = 1 if summary.get("critical", 0) > 0 else 0
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
