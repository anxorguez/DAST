"""Generates HTML, JSON, and SQLite reports from a completed ScanReport."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiosqlite
from jinja2 import Environment, FileSystemLoader, select_autoescape
from loguru import logger

from src.analysis.models import ScanReport, ValidatedFinding
from src.core.config import Settings
from src.core.exceptions import ReportError

_TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"

# Group → field name mapping used to render the effective configuration in
# the HTML report.  Fields not listed here fall under the "Other" bucket so
# new Settings attributes still appear in the report without code changes.
_CONFIG_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Target", ("target_url",)),
    (
        "Speed / footprint",
        ("concurrent_vectors", "concurrent_payloads", "requests_per_second"),
    ),
    (
        "Coverage / scope",
        (
            "max_depth",
            "max_pages",
            "max_payloads_per_vector",
            "payload_types",
            "obfuscation",
            "request_timeout",
            "concurrent_pages",
            "scanner_http_retries",
            "scanner_vector_timeout_seconds",
        ),
    ),
    (
        "Authentication",
        (
            "auth_enabled",
            "auth_url",
            "auth_username",
            "auth_username_field",
            "auth_password_field",
            "auth_success_url",
            "cf_clearance_bridge_enabled",
        ),
    ),
    ("Output", ("output_dir", "scan_name", "log_level")),
    (
        "Test target (DVWA)",
        ("dvwa_security_level", "dvwa_username"),
    ),
)


def _group_config_for_template(config: dict[str, Any]) -> list[tuple[str, list[tuple[str, Any]]]]:
    """Return ``config`` partitioned into ``(group_name, [(key, value), ...])`` pairs.

    Fields listed in ``_CONFIG_GROUPS`` appear in their declared section in
    declared order; remaining fields are gathered under ``Other`` so that
    no setting is silently dropped from the report.
    """
    seen: set[str] = set()
    grouped: list[tuple[str, list[tuple[str, Any]]]] = []
    for group_name, keys in _CONFIG_GROUPS:
        rows: list[tuple[str, Any]] = []
        for key in keys:
            if key in config:
                rows.append((key, config[key]))
                seen.add(key)
        if rows:
            grouped.append((group_name, rows))
    other_rows: list[tuple[str, Any]] = [(k, v) for k, v in config.items() if k not in seen]
    if other_rows:
        grouped.append(("Other", other_rows))
    return grouped


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------


def _fmt_date(dt: datetime) -> str:
    """Format a datetime as ``dd-mm-yyyy``."""
    return dt.strftime("%d-%m-%Y")


def _fmt_time(dt: datetime) -> str:
    """Format a datetime as ``HH:MM`` plus a timezone label.

    Pipeline ``datetime`` values are produced via ``datetime.utcnow()`` and
    are therefore naive — we treat them as UTC for display. Aware datetimes
    print their numeric offset as ``UTC+HH:MM``.
    """
    if dt.tzinfo is None:
        return dt.strftime("%H:%M") + " UTC"
    offset = dt.strftime("%z")
    if offset:
        return f"{dt.strftime('%H:%M')} UTC{offset[:3]}:{offset[3:]}"
    return dt.strftime("%H:%M %Z").strip()


def _url_host(value: str) -> str:
    """Return ``scheme://host[:port]`` for display above the path."""
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return value
    return f"{parts.scheme}://{parts.netloc}"


def _url_path(value: str) -> str:
    """Return ``path[?query][#fragment]`` for display below the host."""
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return ""
    out = parts.path or "/"
    if parts.query:
        out += f"?{parts.query}"
    if parts.fragment:
        out += f"#{parts.fragment}"
    return out


# ---------------------------------------------------------------------------
# SQLite schema
# ---------------------------------------------------------------------------

_CREATE_METADATA = """
CREATE TABLE IF NOT EXISTS scan_metadata (
    scan_id        TEXT PRIMARY KEY,
    target_url     TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    finished_at    TEXT NOT NULL,
    pages_crawled  INTEGER DEFAULT 0,
    vectors_found  INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0
);
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id                  TEXT PRIMARY KEY,
    scan_id             TEXT NOT NULL,
    vuln_type           TEXT NOT NULL,
    severity            TEXT NOT NULL,
    cvss_score          REAL NOT NULL DEFAULT 0.0,
    cvss_vector_string  TEXT NOT NULL DEFAULT '',
    target_url          TEXT NOT NULL,
    field_name          TEXT NOT NULL,
    method              TEXT NOT NULL,
    payload             TEXT NOT NULL,
    evidence            TEXT NOT NULL,
    response_snippet    TEXT,
    confidence          TEXT NOT NULL,
    remediation         TEXT,
    found_at            TEXT NOT NULL,
    response_time_ms    INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scan_metadata(scan_id)
);
"""


class ReportGenerator:
    """Writes findings.db, report.json, and report.html for a completed scan."""

    def __init__(self, settings: Settings, scan_dir: Path) -> None:
        self._settings = settings
        self._scan_dir = scan_dir

    async def generate(self, report: ScanReport) -> None:
        """Persist all three report artefacts to disk.

        Args:
            report: The completed ScanReport produced by the pipeline.

        Raises:
            ReportError: If any artefact cannot be written.
        """
        try:
            await self._write_sqlite(report)
            self._write_json(report)
            self._write_html(report)
            logger.info("Reports written to {d}", d=str(self._scan_dir))
        except Exception as exc:
            raise ReportError(f"Report generation failed: {exc}") from exc

    # -------------------------------------------------------------------
    # SQLite
    # -------------------------------------------------------------------

    async def _write_sqlite(self, report: ScanReport) -> None:
        db_path = self._scan_dir / "findings.db"
        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute(_CREATE_METADATA)
            await db.execute(_CREATE_FINDINGS)

            await db.execute(
                """INSERT OR REPLACE INTO scan_metadata
                   (scan_id, target_url, started_at, finished_at,
                    pages_crawled, vectors_found, total_findings)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    report.scan_id,
                    report.target_url,
                    report.started_at.isoformat(),
                    report.finished_at.isoformat(),
                    report.pages_crawled,
                    report.vectors_found,
                    len(report.findings),
                ),
            )

            for finding in report.findings:
                await db.execute(
                    """INSERT OR REPLACE INTO findings
                       (id, scan_id, vuln_type, severity, cvss_score, cvss_vector_string,
                        target_url, field_name, method, payload, evidence,
                        response_snippet, confidence, remediation, found_at,
                        response_time_ms)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    _finding_row(finding, report.scan_id),
                )

            await db.commit()
        logger.debug("SQLite database written: {p}", p=str(db_path))

    # -------------------------------------------------------------------
    # JSON
    # -------------------------------------------------------------------

    def _write_json(self, report: ScanReport) -> None:
        json_path = self._scan_dir / "report.json"
        data = _report_to_dict(report)
        with json_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
        logger.debug("JSON report written: {p}", p=str(json_path))

    # -------------------------------------------------------------------
    # HTML
    # -------------------------------------------------------------------

    def _write_html(self, report: ScanReport) -> None:
        if not _TEMPLATES_DIR.is_dir():
            raise ReportError(f"Templates directory not found: {_TEMPLATES_DIR}")

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
        )
        env.filters["urlhost"] = _url_host
        env.filters["urlpath"] = _url_path
        template = env.get_template("report.html.j2")
        duration_secs = (report.finished_at - report.started_at).total_seconds()
        rendered = template.render(
            report=report,
            generated_at=datetime.utcnow(),
            duration_seconds=duration_secs,
            config=report.config,
            config_groups=_group_config_for_template(report.config),
            cli_command=report.cli_command,
            started_date=_fmt_date(report.started_at),
            started_time=_fmt_time(report.started_at),
            finished_date=_fmt_date(report.finished_at),
            finished_time=_fmt_time(report.finished_at),
            scanner_health=report.scanner_health,
            crawl_stats=report.crawl_stats,
            scan_degraded=report.scanner_health.completion_rate_pct < 80.0,
        )

        html_path = self._scan_dir / "report.html"
        with html_path.open("w", encoding="utf-8") as fh:
            fh.write(rendered)
        logger.debug("HTML report written: {p}", p=str(html_path))


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _finding_row(finding: ValidatedFinding, scan_id: str) -> tuple[object, ...]:
    raw = finding.raw
    return (
        finding.id,
        scan_id,
        raw.vuln_type.value,
        finding.severity.value,
        finding.cvss_score,
        finding.cvss_vector_string,
        raw.vector.target_url,
        raw.vector.field_name,
        raw.vector.method,
        raw.payload,
        raw.evidence,
        raw.response_snippet,
        raw.confidence.value,
        finding.remediation,
        raw.found_at.isoformat(),
        raw.response_time_ms,
    )


def _report_to_dict(report: ScanReport) -> dict[str, object]:
    # Build the summary block.  ``report.summary`` already contains the
    # severity counts; we layer ``scanner_health`` on top so a JSON
    # consumer can read both groups under ``summary``.
    summary: dict[str, object] = dict(report.summary)
    summary["scanner_health"] = report.scanner_health.to_dict()
    return {
        "scan_id": report.scan_id,
        "target_url": report.target_url,
        "cli_command": report.cli_command,
        "started_at": report.started_at.isoformat(),
        "finished_at": report.finished_at.isoformat(),
        "duration_seconds": (report.finished_at - report.started_at).total_seconds(),
        "pages_crawled": report.pages_crawled,
        "vectors_found": report.vectors_found,
        "total_findings": len(report.findings),
        "summary": summary,
        "crawl_stats": report.crawl_stats.to_dict(),
        "config": report.config,
        "findings": [_finding_to_dict(f) for f in report.findings],
    }


def _finding_to_dict(finding: ValidatedFinding) -> dict[str, object]:
    raw = finding.raw
    return {
        "id": finding.id,
        "severity": finding.severity.value,
        "cvss_score": finding.cvss_score,
        "cvss_vector_string": finding.cvss_vector_string,
        "vuln_type": raw.vuln_type.value,
        "target_url": raw.vector.target_url,
        "field_name": raw.vector.field_name,
        "method": raw.vector.method,
        "surface": raw.vector.surface.value,
        "payload": raw.payload,
        "evidence": raw.evidence,
        "confidence": raw.confidence.value,
        "remediation": finding.remediation,
        "response_time_ms": raw.response_time_ms,
        "found_at": raw.found_at.isoformat(),
        "response_snippet": raw.response_snippet,
    }
