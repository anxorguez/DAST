# DAST Framework

[![Lint](https://github.com/your-org/dast-framework/actions/workflows/lint.yml/badge.svg)](https://github.com/your-org/dast-framework/actions/workflows/lint.yml)
[![Test](https://github.com/your-org/dast-framework/actions/workflows/test.yml/badge.svg)](https://github.com/your-org/dast-framework/actions/workflows/test.yml)
[![Docker Build](https://github.com/your-org/dast-framework/actions/workflows/docker-build.yml/badge.svg)](https://github.com/your-org/dast-framework/actions/workflows/docker-build.yml)

A CLI-based Dynamic Application Security Testing framework that automatically detects
eight classes of web vulnerabilities, including SQL Injection, XSS, Command Injection, SSRF,
XXE, Insecure Deserialization, Path Traversal, and Open Redirect.

---

## Table of Contents

1. [Overview](#overview)
2. [Target Application](#target-application)
3. [Architecture](#architecture)
4. [Vulnerability Classes](#vulnerability-classes)
5. [Requirements](#requirements)
6. [Quick Start](#quick-start)
7. [Configuration](#configuration)
8. [Output](#output)
9. [Running Tests](#running-tests)
10. [CI/CD](#cicd)
11. [Security](#security)
12. [Contributing](#contributing)
13. [License](#license)

---

## Overview

DAST Framework is a Python-based security tool developed as a Master Final Project (TFM).
It performs black-box injection testing on web applications by dynamically crawling the target,
identifying injectable parameters, sending attack payloads, and generating a structured
vulnerability report with CVSS 3.1 scores.

Supported vulnerability classes:

| Class | Techniques | CVSS 3.1 |
|---|---|---|
| SQL Injection | error-based, UNION-based, blind boolean, time-based | 9.1 / 3.7 |
| Cross-Site Scripting | reflected, DOM-based, stored (second-pass) | 6.1 / 5.4 |
| Command Injection | error-based, time-based | 9.8 |
| SSRF | in-band: cloud metadata, response-size delta | 5.3 |
| XXE | DTD file read, PHP wrappers, parser error detection | 8.2 |
| Insecure Deserialization | Java / PHP / Python / .NET malformed objects | 9.8 |
| Path Traversal | `../` sequences, URL-encoding bypasses, null-byte | 7.5 |
| Open Redirect | Location header, meta-refresh, JS redirect | 6.1 |

The tool has no graphical interface. All interaction is through the command line, and all
output is written to the filesystem as HTML, JSON, and SQLite files.

---

## Target Application

The framework requires a web application as its scan target. By default it ships with
DVWA (Damn Vulnerable Web App), which is started automatically as part of the Docker
Compose environment.

DVWA is an intentionally vulnerable PHP application designed for practising web security
testing. Source and documentation: https://github.com/digininja/DVWA

Default DVWA credentials used by the framework:

| Field    | Value    |
|----------|----------|
| Username | admin    |
| Password | password |

The security level is set to low by the start.sh script to ensure all vulnerability
classes are detectable.

To scan a different application, set TARGET_URL in your .env file before running.

### Service topology

The Compose environment exposes three equivalent targets in content but different in
exposure, plus the scanner itself:

| Service       | Internal alias | Host port | Purpose                                  |
|---------------|----------------|-----------|------------------------------------------|
| dvwa-origin   | dvwa-origin    | 8080      | Vulnerable target (no filtering)         |
| dvwa-waf      | dvwa           | 8088      | DVWA + ModSecurity v2 + OWASP CRS PL=1   |
| cf-sim        | dvwa-cf        | 8089      | cf_clearance challenge simulator         |
| dast-app      | (n/a)          | (n/a)     | The DAST scanner (run as one-shot)       |

`dvwa-origin` (host port 8080) is the clean instance of DVWA, useful as a baseline.
`dvwa-waf` (host port 8088) is Apache + ModSecurity v2 with the OWASP Core Rule Set in
front of `dvwa-origin`, and it takes the network alias `dvwa` — so any scan launched
with `--url http://dvwa` transparently traverses the WAF. `cf-sim` (host port 8089)
simulates a Cloudflare `cf_clearance` anti-bot challenge in front of `dvwa-origin`,
under the alias `dvwa-cf`. WAF configuration and exclusions are documented in
[`infra/modsecurity/README.md`](./infra/modsecurity/README.md); the simulator in
[`infra/cf-sim/README.md`](./infra/cf-sim/README.md).

| Scan command target            | Goes through                  | Use for                          |
|---------------------------------|-------------------------------|----------------------------------|
| `--url http://dvwa-origin`      | DVWA directly, nothing ahead  | Baseline (no WAF)                |
| `--url http://dvwa`             | ModSecurity WAF               | Validating `--obfuscation`       |
| `--url http://dvwa-cf`          | cf_clearance simulator        | Validating the cookie/UA bridge  |

---

## Architecture

The pipeline runs four modules sequentially:

```
URL target
   |
   v
[Module 1 - Crawler]
   Playwright headless Chromium. BFS traversal up to MAX_DEPTH.
   Intercepts XHR/fetch. Handles optional form-based pre-authentication.
   Output: list of CrawledPage (url, html, forms, links, xhr_endpoints)
   |
   v
[Module 2 - Vector Identification]
   BeautifulSoup4 + lxml parse each page HTML.
   Extracts form fields, URL parameters, event handlers.
   Heuristics assign applicable VulnTypes per field (name, type, enctype,
   default value). Deduplicates by (url, method, field_name).
   Output: list of AttackVector
   |
   v
[Module 3 - Fuzzing Engine]  ← CONCURRENT (asyncio.Semaphore)
   CONCURRENT_VECTORS vectors scanned in parallel.
   Per vector, CONCURRENT_PAYLOADS payloads tested concurrently.
   Time-based payloads are always serialised (dedicated asyncio.Lock).
   Optional rate limiting (REQUESTS_PER_SECOND > 0).
   Scanners:
     SQLiScanner           - error patterns, time delta, UNION markers
     XSSScanner            - payload reflection, DOM-based check
     CMDiScanner           - OS output patterns, time delta
     SSRFScanner           - cloud metadata patterns, response-size delta
     XXEScanner            - DTD entity resolution, parser errors
     DeserializationScanner - exception patterns, HTTP 500 correlation
     PathTraversalScanner  - system file content patterns, FS errors
     OpenRedirectScanner   - Location header, meta-refresh, JS redirect
   3 retries per payload. Finding confirmed at ≥2/3.
   After fuzzing: second crawl pass for stored XSS detection.
   Output: list of RawFinding
   |
   v
[Module 4 - Analysis and Reporting]
   Validator deduplicates and applies confirmation threshold.
   SeverityScorer: maps each finding → CVSSVector via cvss_mapper,
     calculates CVSS 3.1 Base Score, derives severity from numeric bands.
   ReportGenerator writes findings.db (SQLite), report.json, report.html.
   All outputs include cvss_vector_string (e.g. CVSS:3.1/AV:N/AC:L/...).
   Output: ScanReport + files in reports/<scan_id>/
```

### Anti-bot challenges (cf_clearance bridge)

Some real-world targets sit behind an anti-bot layer such as Cloudflare, which issues
a `cf_clearance` cookie only after a JavaScript challenge that a plain HTTP client
cannot solve. The framework's crawler runs a real browser (Playwright) and *can* solve
such challenges; the fuzzer uses `httpx` and cannot. The **cf_clearance bridge** closes
that gap: the crawler captures both the session cookies *and* the `User-Agent` from its
authenticated `BrowserContext`, and the pipeline propagates them to the `HTTPClient`
the fuzzer builds. Propagating the `User-Agent` matters because the challenge cookie is
bound to the UA that requested it — sending the fuzzer's default `httpx` UA would
invalidate the clearance.

The behaviour is selected with `--cf-clearance-mode` (or `CF_CLEARANCE_MODE`):

- `off` (default): no cookie or UA propagation — the fuzzer runs with its own
  session and will receive 403 on every request to a cf-protected target.
- `propagate`: the crawler's cookies and User-Agent are pushed to the fuzzer's
  `HTTPClient`, but no reactive refresh is performed.
- `refresh`: propagation **plus** a reactive refresh — when an upstream answers
  with `X-Cf-Sim-Challenge: expired`/`missing`, the `HTTPClient` re-launches
  Playwright to renew the cookie and UA, then retries the request once.

The `cf-sim` service (see Service topology) is a local fixture that implements
this contract for testing.

---

## Vulnerability Classes

| VulnType | Scanner | Detection technique | Typical CVSS |
|---|---|---|---|
| `sqli` | SQLiScanner | SQL error patterns, UNION marker, time-based delay | 9.1 / 3.7 |
| `xss` | XSSScanner | Payload reflection (verbatim + partial), exec patterns | 6.1 / 5.4 |
| `cmdi` | CMDiScanner | OS command output patterns, time-based delay | 9.8 |
| `ssrf` | SSRFScanner | Cloud metadata content, response size difference | 5.3 |
| `xxe` | XXEScanner | File content reflection, XML parser errors | 8.2 |
| `deserialization` | DeserializationScanner | Deser exception messages, HTTP 500 + serialised payload | 9.8 |
| `path_traversal` | PathTraversalScanner | `/etc/passwd` / `win.ini` content, FS error strings | 7.5 |
| `open_redirect` | OpenRedirectScanner | 3xx Location header, meta-refresh, JS `window.location` | 6.1 |

VulnType heuristics (field name → scanner):

- **SSRF**: url, endpoint, api, webhook, proxy, fetch, load, src, href, callback
- **Path Traversal**: file, filename, path, template, include, dir, download, read, load
- **Open Redirect**: url, redirect, next, return, goto, target, destination, redir, continue
- **CMDi**: cmd, command, exec, execute, shell, ping, host, ip, file, filename, path
- **XXE**: only when form enctype is `application/xml` / `text/xml`
- **Deserialization**: only when default field value resembles serialised data (base64/`O:`/`rO0AB`)

---

## Requirements

- Docker >= 24
- docker compose >= 2.20 (the docker compose subcommand, not docker-compose)
- Bash >= 4 (for start.sh and stop.sh)

No Python installation is required on the host. Everything runs inside containers.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-org/dast-framework.git
cd dast-framework

# 2. Copy the environment template
cp .env.example .env

# 3. Start the backend, WAF and cf-sim, and wait for them to be ready
./start.sh

# 4a. Baseline scan against DVWA WITHOUT the WAF (v3-style)
docker compose run --rm dast-app --url http://dvwa-origin \
    --concurrent-vectors 5 --concurrent-payloads 10 --requests-per-second 0 \
    --depth 3 --max-pages 100 --max-payloads-per-vector 50 \
    --payload-types sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect \
    --request-timeout 30

# 4b. Scan against DVWA THROUGH the ModSecurity WAF, exercising --obfuscation
docker compose run --rm dast-app --url http://dvwa \
    --obfuscation none,double_url,base64 \
    --concurrent-vectors 5 --concurrent-payloads 10 --requests-per-second 0 \
    --depth 3 --max-pages 100 --max-payloads-per-vector 50 \
    --payload-types sqli,xss,cmdi,ssrf,xxe,deserialization,path_traversal,open_redirect \
    --request-timeout 30

# 5. Find your report in ./reports/outputs/<scan_id>/
ls reports/outputs/
```

---

## Configuration

All settings are read from environment variables (.env file or shell environment).

| Variable                  | Default                                      | Description                                         |
|---------------------------|----------------------------------------------|-----------------------------------------------------|
| TARGET_URL                | http://dvwa                                  | URL of the application to scan                      |
| OUTPUT_DIR                | /app/reports                                 | Output directory inside the container               |
| LOG_LEVEL                 | INFO                                         | Log level: DEBUG, INFO, WARNING, ERROR              |
| MAX_DEPTH                 | 3                                            | Maximum BFS crawling depth                          |
| MAX_PAGES                 | 100                                          | Maximum number of pages to visit                    |
| REQUEST_TIMEOUT           | 30                                           | HTTP request timeout in seconds                     |
| CONCURRENT_PAGES          | 5                                            | Pages processed concurrently by Playwright          |
| AUTH_ENABLED              | false                                        | Enable pre-scan form-based login                    |
| AUTH_URL                  | (empty)                                      | Login form URL                                      |
| AUTH_USERNAME             | (empty)                                      | Username to submit in the login form                |
| AUTH_PASSWORD             | (empty)                                      | Password to submit in the login form                |
| AUTH_USERNAME_FIELD       | username                                     | name attribute of the username input                |
| AUTH_PASSWORD_FIELD       | password                                     | name attribute of the password input                |
| AUTH_SUCCESS_URL          | (empty)                                      | URL to verify successful login redirect             |
| PAYLOAD_TYPES             | sqli,xss,cmdi,ssrf,xxe,deserialization,…     | Comma-separated list of enabled vulnerability types |
| MAX_PAYLOADS_PER_VECTOR   | 50                                           | Maximum payloads tested per attack vector           |
| CONCURRENT_VECTORS        | 5                                            | Number of vectors fuzzed concurrently               |
| CONCURRENT_PAYLOADS       | 10                                           | Payloads tested in parallel per scanner             |
| REQUESTS_PER_SECOND       | 0                                            | Rate limit (0 = unlimited)                          |
| CF_CLEARANCE_MODE         | off                                          | cf_clearance bridge mode: off / propagate / refresh |
| DVWA_SECURITY_LEVEL       | low                                          | DVWA security level for integration tests           |
| DVWA_USERNAME             | admin                                        | DVWA login username                                 |
| DVWA_PASSWORD             | password                                     | DVWA login password                                 |

CLI flags always take priority over environment variables and built-in defaults.

### Authenticating against DVWA

DVWA redirects every page to `login.php` until a session cookie is set, so a scan
with `AUTH_ENABLED=false` will only fuzz the login form and will not reach any of
the vulnerable endpoints (sqli, xss_r, xss_s, exec, file_inclusion, ...). A
warning is logged when the crawl stops at a single login page without auth
enabled.

To scan DVWA properly, add the following block to your `.env`:

```env
# --- Authentication against DVWA ---
AUTH_ENABLED=true
AUTH_URL=http://dvwa/login.php
AUTH_USERNAME=admin
AUTH_PASSWORD=password
AUTH_USERNAME_FIELD=username
AUTH_PASSWORD_FIELD=password
AUTH_SUCCESS_URL=http://dvwa/index.php
```

With these values the crawler logs in once before the BFS begins, reuses the
`PHPSESSID` cookie for every subsequent request, and is able to discover and
fuzz the vulnerable pages: `/vulnerabilities/sqli/?id=...`,
`/vulnerabilities/xss_r/?name=...`, `/vulnerabilities/xss_s/`,
`/vulnerabilities/exec/`, `/vulnerabilities/fi/?page=...`, and others.

### Tuning parameters

Eight tuning knobs are exposed directly on the CLI, split between two groups
with very different semantics. Each flag can also be set via its environment
variable (CLI wins on conflict).

#### Velocidad / huella

These flags control **how many requests run in parallel and at what rate**.
They do NOT change what is tested, only how fast and how visible the scan is
to the target's logs/IDS.

| CLI flag                | Env var                | Default | Description                                       |
|-------------------------|------------------------|---------|---------------------------------------------------|
| `--concurrent-vectors`  | `CONCURRENT_VECTORS`   | 5       | Vectors fuzzed in parallel                        |
| `--concurrent-payloads` | `CONCURRENT_PAYLOADS`  | 10      | Payloads tested in parallel per scanner           |
| `--requests-per-second` | `REQUESTS_PER_SECOND`  | 0       | Global rate limit applied across ALL scanners (0 = unlimited) |

**Note**: `--requests-per-second` is a single shared limiter — the configured
rate is the *combined* outbound rate across every scanner and vector, not a
per-scanner rate.

#### Cobertura / alcance

These flags control **what parts of the target are explored and how
thoroughly**. They are the levers that change the number of findings.

| CLI flag                     | Env var                  | Default | Description                                         |
|------------------------------|--------------------------|---------|-----------------------------------------------------|
| `--depth`                    | `MAX_DEPTH`              | 3       | Maximum BFS depth followed by the crawler           |
| `--max-pages`                | `MAX_PAGES`              | 100     | Hard cap on pages crawled                           |
| `--max-payloads-per-vector`  | `MAX_PAYLOADS_PER_VECTOR`| 50      | Max payloads per (vector × scanner). Dominant lever |
| `--payload-types`            | `PAYLOAD_TYPES`          | (all 8) | CSV of active scanner classes                       |
| `--request-timeout`          | `REQUEST_TIMEOUT`        | 30      | HTTP request timeout in seconds                     |

`--payload-types` accepts any combination of: `sqli`, `xss`, `cmdi`, `ssrf`,
`xxe`, `deserialization`, `path_traversal`, `open_redirect`.

#### Recommended combinations

The three columns below reproduce the behaviour of the legacy
default/aggressive/stealth profiles, now expressed in terms of the eight flags.

| Style          | cv | cp | rps | depth | pages | mppv | payload-types  |
|----------------|----|----|-----|-------|-------|------|----------------|
| **minimal**    | 1  | 1  | 1   | 1     | 5     | 5    | sqli           |
| **balanced**   | 5  | 10 | 0   | 3     | 100   | 50   | (all 8)        |
| **aggressive** | 10 | 20 | 0   | 5     | 500   | 200  | (all 8)        |
| **stealth**    | 2  | 3  | 5   | 2     | 50    | 20   | (all 8)        |

The HTML and JSON reports include an "Effective Configuration" block dumping
every Settings field used for the run, so the analyst can verify exactly which
combination produced the findings.

---

## Output

Each scan creates a uniquely named folder under reports/:

```
reports/
+-- 20250315_142301_3f9a1c2b/
    +-- findings.db     SQLite database with all validated findings
    +-- report.html     Full HTML report rendered from Jinja2 template
    +-- report.json     Machine-readable report (same data as HTML)
    +-- scan.log        Complete Loguru log for this scan session
```

The reports/ directory is excluded from version control (.gitignore).
Only reports/.gitkeep is committed.

---

## Running Tests

Install development dependencies first (or use the Docker environment):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
playwright install chromium
```

Run unit tests (no external services needed):

```bash
pytest tests/unit/ -v --cov=src --cov-report=term-missing
```

Run integration tests against DVWA (requires ./start.sh to have been run first):

```bash
pytest tests/integration/ -v -m integration
```

---

## CI/CD

Three GitHub Actions workflows run on every push and pull request to main:

| Workflow     | File                                    | What it does                                               |
|--------------|-----------------------------------------|------------------------------------------------------------|
| Lint         | .github/workflows/lint.yml              | ruff check, ruff format check, mypy strict                |
| Test         | .github/workflows/test.yml              | Spins up DVWA, runs unit + integration tests, uploads coverage |
| Docker Build | .github/workflows/docker-build.yml      | Builds multi-arch image, pushes to GHCR on tag/main       |

---

## Security

Vulnerability reports for the framework itself must be submitted via GitHub Security
Advisories. See SECURITY.md for the full policy and response SLA.

This tool is designed exclusively for use against applications you own or have explicit
written permission to test. Unauthorised use against third-party systems may violate
applicable laws. The authors accept no liability for misuse.

---

## Contributing

See CONTRIBUTING.md for the development setup, code conventions, and pull request process.

---

## License

MIT License. See LICENSE for the full text.
