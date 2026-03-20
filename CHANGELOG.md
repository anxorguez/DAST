# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
