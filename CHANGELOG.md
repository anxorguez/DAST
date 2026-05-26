# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — ModSecurity WAF in front of DVWA (Fase 1)

- WAF en compose: nuevo servicio `dvwa-waf` (Apache + ModSecurity v2 +
  OWASP CRS 4.x, PARANOIA=1) delante de DVWA, alias de red `dvwa`.
- Directorio `infra/modsecurity/` con exclusiones para el flujo de auth.
- README específico en `infra/modsecurity/README.md`.

### Changed — WAF topology

- Servicio `dvwa` renombrado a `dvwa-origin`. El alias `dvwa` apunta
  ahora al WAF. Los escaneos baseline sin WAF usan `--url
  http://dvwa-origin`.
- `start.sh`: levanta `dvwa-waf` y espera health en puerto 8088.
- `scan_profiles_v3.md` y `run_all_scans_v3.sh`: comandos actualizados a
  `dvwa-origin` para mantener el contrato de baseline sin WAF.
- `scan_profiles_v4_obfuscation.md` y `run_all_scans_v4.sh`: target
  pivotado de `nginx-waf` a `dvwa` (que ahora es el WAF).
- Lecturas esperadas de v4 referencian IDs del OWASP CRS en lugar de
  reglas regex ad-hoc.

### Removed

- (Ya estaba quitado antes de este cambio: el servicio nginx-waf y el
  directorio `infra/nginx-waf/` del experimento previo.)

### Added — cf_clearance bridge (Fase 2)

- Servicio `cf-sim`: simulador del contrato `cf_clearance` de Cloudflare,
  alias de red `dvwa-cf`, expone puerto host 8089.
- Flag CLI `--cf-clearance-bridge`: activa el refresh reactivo del
  cookie cuando un upstream devuelve `X-Cf-Sim-Challenge` expired/missing.
- HTTPClient: nuevo parámetro `user_agent` que se propaga desde el
  Playwright BrowserContext. Previene el `ua_mismatch` que invalidaría
  el cf_clearance.
- Crawler: método público `refresh_session_async` para renovar cookies +
  UA desde Playwright bajo demanda del HTTPClient.
- Tests de integración en `tests/integration/test_cf_clearance_bridge.py`
  y unitarios en `tests/unit/test_http_client_cf_clearance.py`.

### Changed — cf_clearance bridge

- HTTPClient acepta opcionalmente un callback de refresh; el header
  `User-Agent` ahora se respeta cuando viene del crawler en lugar de
  caer al default de httpx.
- `Settings` gana el campo `cf_clearance_bridge_enabled` (env
  `CF_CLEARANCE_BRIDGE_ENABLED`), incluido en el dump de Effective
  Configuration del reporte.

### Added — Coverage knobs in the CLI and effective-config dump in the report

- Four new CLI flags expose what used to be implicit defaults, giving the
  analyst real control over coverage rather than only speed:
  - `--max-payloads-per-vector` (env `MAX_PAYLOADS_PER_VECTOR`, default 50)
    — dominant lever for cost and intrusiveness per (vector × scanner).
  - `--max-pages` (env `MAX_PAGES`, default 100) — absolute crawl page cap.
  - `--payload-types` (env `PAYLOAD_TYPES`, default = full CSV of all eight
    scanner classes) — selects which scanner classes are active.
  - `--request-timeout` (env `REQUEST_TIMEOUT`, default 30) — HTTP timeout.
- The startup banner now logs the full effective Settings dump
  (`Effective settings: {...}`), with `auth_password`, `dvwa_password`, and
  `db_path` redacted.
- `ScanReport` gained a `config: dict[str, Any]` field. `report.json`
  serialises it; the HTML report renders an "Effective Configuration"
  section grouped into Target / Speed / Coverage / Authentication / Output.

### Changed — `--requests-per-second` is now a true global rate limit

- **BREAKING (behaviour, not API)**: Previously each scanner instance applied
  its own `1/rps` sleep, so the effective outbound rate was multiplied by
  `concurrent_vectors × scanners_per_vector` (≈24× at default settings).
  Now a single `GlobalRateLimiter` is created in the pipeline and shared
  across every scanner, so `--requests-per-second N` corresponds 1:1 to N
  combined outbound requests per second.
- New module `src/core/rate_limiter.py` (`GlobalRateLimiter` + factory
  `get_rate_limiter`). `BaseScanner.__init__` and `Fuzzer.__init__` accept
  an optional `rate_limiter`; subclasses propagate it via `super().__init__`.

### Changed — `docker-compose.yml` no longer overrides Settings defaults

- The `dast-app` service `environment:` block was rewritten as a list of
  pass-through entries (`- VAR`) so a host variable is forwarded only when
  it is actually defined. With no host overrides, Pydantic Settings defaults
  in `src/core/config.py` are the single source of truth.
- This fixes an issue where `PAYLOAD_TYPES: ${PAYLOAD_TYPES:-sqli,xss,cmdi}`
  silently restricted scans to three scanner classes by default (omitting
  the five new ones added in Mejora 1).
- `.env.example` now ships the full default for `PAYLOAD_TYPES` and includes
  `MAX_PAYLOADS_PER_VECTOR`, `MAX_PAGES`, `REQUEST_TIMEOUT` for completeness.

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
