# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — CLI tuning flags replace scan profiles

- **BREAKING**: Removed the `--profile` CLI flag and the `SCAN_PROFILE` environment
  variable. The YAML files under `config/` (`default.yaml`, `aggressive.yaml`,
  `stealth.yaml`) have been deleted; the directory no longer exists.
- Added four explicit tuning flags on the CLI, each with an equivalent env var:
  - `--concurrent-vectors` (`CONCURRENT_VECTORS`, default 5)
  - `--concurrent-payloads` (`CONCURRENT_PAYLOADS`, default 10)
  - `--requests-per-second` (`REQUESTS_PER_SECOND`, default 0 = unlimited)
  - `--depth` (`MAX_DEPTH`, default 3)
- `Settings.scan_profile`, its validator, and the `_load_profile`/`get_settings`
  YAML branch are removed. `get_settings()` now applies overrides on top of env
  defaults only. CLI flags take priority over environment variables.
- HTML report replaces the "Scan Profile" row with explicit rows for each tuning
  parameter (`concurrent_vectors`, `concurrent_payloads`, `requests_per_second`,
  `max_depth`).
- `pyyaml` removed from runtime dependencies (no longer needed once profile YAMLs
  are gone).

### Added — Mejora 3: CVSS 3.1 Real Scoring

- New module `src/analysis/cvss.py` implementing the complete CVSS 3.1 Base Score formula.
  Includes enums (`CVSSAttackVector`, `CVSSAttackComplexity`, `CVSSPrivilegesRequired`,
  `CVSSUserInteraction`, `CVSSScope`, `CVSSImpact`), `CVSSVector` dataclass,
  `calculate_base_score()`, `vector_to_string()`, and the spec-compliant `_roundup()` function.
- New module `src/analysis/cvss_mapper.py` mapping each `RawFinding` (vuln type + sub-type)
  to a full `CVSSVector` with documented justifications per vulnerability class.
- `SeverityScorer` refactored to use `calculate_base_score()` instead of fixed rules.
  Severity is derived from the standard CVSS bands (≥9.0 CRITICAL, ≥7.0 HIGH, ≥4.0 MEDIUM,
  ≥0.1 LOW, 0.0 INFO).
- `ValidatedFinding` extended with `cvss_vector_string: str` field.
- Report outputs (SQLite `findings` table, JSON, HTML) now include the CVSS 3.1 vector string.
- Unit tests: `tests/unit/test_cvss.py` (score formula, known CVE values) and
  `tests/unit/test_cvss_mapper.py` (all vuln types + sub-types).

### Added — Mejora 2: Concurrent Payload Execution

- `BaseScanner.scan()` now processes payloads concurrently using `asyncio.Semaphore`,
  bounded by the new `concurrent_payloads` setting (default 10).
- Time-based payloads (`sleep`, `waitfor delay`, `pg_sleep`, `ping`) are automatically
  serialised behind a dedicated `asyncio.Lock` to preserve timing accuracy.
- `Fuzzer.run()` processes vectors concurrently, bounded by the new `concurrent_vectors`
  setting (default 5).  Uses `asyncio.gather` over tasks, one per vector.
- New `Settings` fields: `concurrent_vectors` (int, default 5), `concurrent_payloads`
  (int, default 10), `requests_per_second` (int, default 0 = unlimited).
- Rate limiting: when `requests_per_second > 0`, each payload probe sleeps
  `1/rps` seconds before sending.
- Scan profiles updated:
  - `default`: concurrent_vectors=5, concurrent_payloads=10, requests_per_second=0
  - `aggressive`: concurrent_vectors=10, concurrent_payloads=20, requests_per_second=0
  - `stealth`: concurrent_vectors=2, concurrent_payloads=3, requests_per_second=5

### Added — Mejora 1: New Vulnerability Classes

- Five new `VulnType` enum values: `SSRF`, `XXE`, `DESERIALIZATION`, `PATH_TRAVERSAL`,
  `OPEN_REDIRECT`.
- New `SurfaceType.XML_BODY` value for XML-body attack vectors.
- Five new scanner modules, each following the `BaseScanner` pattern:
  - `src/fuzzing/ssrf_scanner.py` — in-band SSRF detection (cloud metadata patterns,
    `/etc/passwd`, response size difference heuristic).
  - `src/fuzzing/xxe_scanner.py` — XML External Entity via DTD payloads; detects
    file-content reflection and XML parser errors.
  - `src/fuzzing/deserialization_scanner.py` — malformed serialised object injection
    (Java, PHP, Python, .NET); detects deserialization exceptions and HTTP 500.
  - `src/fuzzing/path_traversal_scanner.py` — `../` traversal sequences; detects
    system file content (`/etc/passwd`, `win.ini`) and filesystem errors.
  - `src/fuzzing/open_redirect_scanner.py` — external URL injection; detects 3xx
    `Location` header, `<meta http-equiv="refresh">`, and JS `window.location`.
- Payload files added under `payloads/`:
  - `ssrf/internal_urls.txt` (44 payloads) and `ssrf/cloud_metadata.txt` (25 payloads).
  - `xxe/entities.txt` (20 payloads).
  - `deserialization/malformed.txt` (Java, PHP, Python pickle, .NET, YAML).
  - `path_traversal/unix.txt` (40 payloads) and `path_traversal/windows.txt` (25 payloads).
  - `open_redirect/urls.txt` (25 payloads).
- `VectorAnalyzer` extended with heuristic sets for SSRF, Path Traversal, Open Redirect,
  XXE (XML enctype detection), and Deserialization (base64/serialised default value detection).
- `SeverityScorer` extended with fixed rules (pre-CVSS): SSRF→HIGH 7.5, XXE→CRITICAL 9.0,
  Deserialization→CRITICAL 9.5, Path Traversal→HIGH 7.0, Open Redirect→MEDIUM 4.0.
  (These rules are now replaced by CVSS 3.1 calculation from Mejora 3.)
- `PayloadLoader._VULN_DIR` extended with the five new directories.
- `Settings.payload_types` default updated to include all eight vulnerability types.
- All three YAML scan profiles updated accordingly.
- Unit tests for each new scanner: `tests/unit/test_{ssrf,xxe,deserialization,
  path_traversal,open_redirect}_scanner.py`.

### Added — Initial Implementation

- Module 1: Dynamic crawler with Playwright headless Chromium, BFS traversal, XHR interception,
  and optional form-based pre-authentication.
- Module 2: Attack vector identification via DOM parsing (BeautifulSoup4 + lxml). Extracts form
  fields, URL parameters, and event handlers. Deduplicates vectors by (url, method, field).
- Module 3: Injection and fuzzing engine with modular scanners for SQL Injection (error-based,
  blind boolean, time-based, UNION-based), XSS (reflected, DOM-based, stored second-pass),
  and Command Injection (error-based, time-based).
- Module 4: Analysis and reporting. Validates findings with 2-of-3 retry confirmation rule.
  Assigns severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) by vulnerability type. Generates HTML
  and JSON reports via Jinja2. Persists findings in per-scan SQLite database.
- Payload repository with real-world payloads from SecLists and PayloadsAllTheThings,
  organised by vulnerability type and technique.
- Three scan profiles: default, aggressive, stealth (YAML configuration files).
- Docker Compose environment: dast-app, DVWA, MariaDB.
- Shell scripts: start.sh, stop.sh, entrypoint.sh (with minimal iptables firewall).
- GitHub Actions CI/CD: lint workflow (ruff + mypy), test workflow (pytest against DVWA),
  and Docker build/push workflow.
