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
"""

from __future__ import annotations

import asyncio
import binascii
import os
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
    "--request-timeout",
    "request_timeout",
    default=30,
    show_default=True,
    type=int,
    envvar="REQUEST_TIMEOUT",
    help="[Cobertura] HTTP request timeout in seconds.",
)
# --- Output / logging --------------------------------------------------------
@click.option(
    "--output",
    default=None,
    envvar="OUTPUT_DIR",
    help="Directory where scan output folders are created. Defaults to ./reports.",
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
    request_timeout: int,
    output: str | None,
    log_level: str | None,
) -> None:
    """DAST Framework — automated injection vulnerability scanner."""
    # ------------------------------------------------------------------
    # Build settings
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
        "request_timeout": request_timeout,
    }
    if output:
        overrides["output_dir"] = output
    if log_level:
        overrides["log_level"] = log_level

    settings = get_settings(**overrides)

    # ------------------------------------------------------------------
    # Create scan output directory
    # ------------------------------------------------------------------
    scan_id = _make_scan_id()

    # Prefer SCAN_DIR from environment (set by entrypoint.sh) so both the
    # shell script and Python agree on the same directory.
    scan_dir_env = os.environ.get("SCAN_DIR", "")
    if scan_dir_env:
        scan_dir = Path(scan_dir_env)
    else:
        base = Path(settings.output_dir)
        scan_dir = base / scan_id

    scan_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Configure logging
    # ------------------------------------------------------------------
    setup_logger(log_level=settings.log_level, log_file=scan_dir / "scan.log")

    logger.info(
        "DAST Framework starting | url={u} | cv={cv} | cp={cp} | rps={rps} | "
        "depth={d} | max_pages={mp} | max_payloads_per_vector={mppv} | "
        "payload_types={pt} | request_timeout={rt} | scan_id={s}",
        u=url,
        cv=concurrent_vectors,
        cp=concurrent_payloads,
        rps=requests_per_second,
        d=depth,
        mp=max_pages,
        mppv=max_payloads_per_vector,
        pt=payload_types,
        rt=request_timeout,
        s=scan_id,
    )
    logger.info("Effective settings: {s}", s=_safe_dump(settings))

    # ------------------------------------------------------------------
    # Run pipeline
    # ------------------------------------------------------------------
    pipeline = Pipeline(settings, scan_dir)

    try:
        report = asyncio.run(pipeline.run())
    except DASTError as exc:
        logger.error("Scan aborted: {e}", e=exc)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error: {e}", e=exc)
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
