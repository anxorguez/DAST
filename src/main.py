"""CLI entry point for the DAST framework.

Usage:
    python -m src.main --url http://dvwa --profile default
    python -m src.main --url http://target --profile aggressive --log-level DEBUG
"""

from __future__ import annotations

import asyncio
import binascii
import os
import sys
from datetime import datetime
from pathlib import Path

import click
from loguru import logger

from src.core.config import get_settings
from src.core.exceptions import DASTError
from src.core.logger import setup_logger
from src.pipeline import Pipeline


def _make_scan_id() -> str:
    """Generate a unique scan ID: YYYYMMDD_HHMMSS_<8 random hex chars>."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    rand_hex = binascii.hexlify(os.urandom(4)).decode("ascii")
    return f"{timestamp}_{rand_hex}"


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--url",
    required=True,
    envvar="TARGET_URL",
    help="Target URL to scan (e.g. http://dvwa).",
)
@click.option(
    "--profile",
    default="default",
    show_default=True,
    envvar="SCAN_PROFILE",
    type=click.Choice(["default", "aggressive", "stealth"], case_sensitive=False),
    help="Scan profile controlling depth, payload count, and timeouts.",
)
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
    profile: str,
    output: str | None,
    log_level: str | None,
) -> None:
    """DAST Framework — automated injection vulnerability scanner."""
    # ------------------------------------------------------------------
    # Build settings
    # ------------------------------------------------------------------
    overrides: dict[str, object] = {"target_url": url, "scan_profile": profile}
    if output:
        overrides["output_dir"] = output
    if log_level:
        overrides["log_level"] = log_level

    settings = get_settings(profile=profile, **overrides)

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
        "DAST Framework starting | url={u} | profile={p} | scan_id={s}",
        u=url,
        p=profile,
        s=scan_id,
    )

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
