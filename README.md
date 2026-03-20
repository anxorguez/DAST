# DAST Framework

[![Lint](https://github.com/your-org/dast-framework/actions/workflows/lint.yml/badge.svg)](https://github.com/your-org/dast-framework/actions/workflows/lint.yml)
[![Test](https://github.com/your-org/dast-framework/actions/workflows/test.yml/badge.svg)](https://github.com/your-org/dast-framework/actions/workflows/test.yml)
[![Docker Build](https://github.com/your-org/dast-framework/actions/workflows/docker-build.yml/badge.svg)](https://github.com/your-org/dast-framework/actions/workflows/docker-build.yml)

A CLI-based Dynamic Application Security Testing framework that automatically detects
SQL Injection, Cross-Site Scripting, and Command Injection vulnerabilities in web applications.

---

## Table of Contents

1. [Overview](#overview)
2. [Target Application](#target-application)
3. [Architecture](#architecture)
4. [Requirements](#requirements)
5. [Quick Start](#quick-start)
6. [Configuration](#configuration)
7. [Output](#output)
8. [Running Tests](#running-tests)
9. [CI/CD](#cicd)
10. [Security](#security)
11. [Contributing](#contributing)
12. [License](#license)

---

## Overview

DAST Framework is a Python-based security tool developed as a Master Final Project (TFM).
It performs black-box injection testing on web applications by dynamically crawling the target,
identifying injectable parameters, sending attack payloads, and generating a structured
vulnerability report.

Supported vulnerability classes:

- SQL Injection (error-based, blind boolean, time-based, UNION-based)
- Cross-Site Scripting (reflected, DOM-based, stored with second-pass verification)
- Command Injection (error-based, time-based)

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
   Deduplicates by (url, method, field_name).
   Output: list of AttackVector
   |
   v
[Module 3 - Fuzzing Engine]
   For each vector x each enabled vulnerability type:
     SQLiScanner  - error patterns, time delta, UNION markers
     XSSScanner   - payload reflection, DOM-based check
     CMDiScanner  - OS output patterns, time delta
   3 retries per payload. Findings confirmed at 2/3.
   After fuzzing: second crawl pass for stored XSS detection.
   Output: list of RawFinding
   |
   v
[Module 4 - Analysis and Reporting]
   Validator deduplicates and applies confirmation threshold.
   SeverityScorer assigns CRITICAL/HIGH/MEDIUM/LOW/INFO by fixed rules.
   ReportGenerator writes findings.db (SQLite), report.json, report.html.
   Output: ScanReport + files in reports/<scan_id>/
```

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

# 3. Start DVWA and wait for it to be ready
./start.sh

# 4. Run a scan against DVWA with the default profile
docker compose run --rm dast-app --url http://dvwa --profile default

# 5. Find your report in ./reports/<scan_id>/
ls reports/
```

---

## Configuration

All settings are read from environment variables (.env file or shell environment).

| Variable                  | Default         | Description                                         |
|---------------------------|-----------------|-----------------------------------------------------|
| TARGET_URL                | http://dvwa     | URL of the application to scan                      |
| SCAN_PROFILE              | default         | Scan profile: default, aggressive, stealth          |
| OUTPUT_DIR                | /app/reports    | Output directory inside the container               |
| LOG_LEVEL                 | INFO            | Log level: DEBUG, INFO, WARNING, ERROR              |
| MAX_DEPTH                 | 3               | Maximum BFS crawling depth                          |
| MAX_PAGES                 | 100             | Maximum number of pages to visit                    |
| REQUEST_TIMEOUT           | 30              | HTTP request timeout in seconds                     |
| CONCURRENT_PAGES          | 5               | Pages processed concurrently by Playwright          |
| AUTH_ENABLED              | false           | Enable pre-scan form-based login                    |
| AUTH_URL                  | (empty)         | Login form URL                                      |
| AUTH_USERNAME             | (empty)         | Username to submit in the login form                |
| AUTH_PASSWORD             | (empty)         | Password to submit in the login form                |
| AUTH_USERNAME_FIELD       | username        | name attribute of the username input                |
| AUTH_PASSWORD_FIELD       | password        | name attribute of the password input                |
| AUTH_SUCCESS_URL          | (empty)         | URL to verify successful login redirect             |
| PAYLOAD_TYPES             | sqli,xss,cmdi   | Comma-separated list of enabled vulnerability types |
| MAX_PAYLOADS_PER_VECTOR   | 50              | Maximum payloads tested per attack vector           |
| DVWA_SECURITY_LEVEL       | low             | DVWA security level for integration tests           |
| DVWA_USERNAME             | admin           | DVWA login username                                 |
| DVWA_PASSWORD             | password        | DVWA login password                                 |

Scan profiles (config/default.yaml, config/aggressive.yaml, config/stealth.yaml)
override these defaults. Profile values are in turn overridden by environment variables.

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
