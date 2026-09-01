# Contributing to DAST Framework

Thank you for your interest in contributing. This document explains how to report bugs,
propose features, and submit pull requests.

## Table of Contents

1. [Reporting a Bug](#reporting-a-bug)
2. [Proposing a Feature](#proposing-a-feature)
3. [Development Setup](#development-setup)
4. [Code Conventions](#code-conventions)
5. [Submitting a Pull Request](#submitting-a-pull-request)
6. [Review Process](#review-process)

---

## Reporting a Bug

1. Search existing issues first to avoid duplicates.
2. Open a new issue using the **Bug Report** template.
3. Include the DAST version (git commit hash), your OS, Docker version, and the full
   error output.
4. If the bug involves a security vulnerability, do **not** open a public issue.
   Follow the process in [SECURITY.md](SECURITY.md) instead.

## Proposing a Feature

1. Search existing issues and discussions to see if the feature has already been proposed.
2. Open a new issue using the **Feature Request** template.
3. Describe the problem the feature solves, not just the solution.
4. Be prepared to discuss alternative approaches before implementation begins.

## Development Setup

Requirements: Python 3.12+, Docker, docker compose.

```bash
# Clone the repository
git clone https://github.com/anxorguez/DAST.git
cd DAST

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install Playwright browsers
playwright install chromium

# Copy environment template
cp .env.example .env
```

## Code Conventions

All contributions must pass the following checks before a PR is merged.

### Linting and formatting

```bash
ruff check src/ tests/
ruff format src/ tests/
```

### Static type checking

```bash
mypy src/
```

Strict mypy mode is enabled. All public functions and methods must have type annotations.

### Tests

```bash
# Unit tests only (no external services needed)
pytest tests/unit/ -v --cov=src --cov-report=term-missing

# Integration tests (requires DVWA to be running via ./start.sh)
pytest tests/integration/ -v -m integration
```

All new code must be covered by tests. Keep coverage above 70 % for the `src/` package.

### Commit messages

Use the conventional commits format:

```
<type>(<scope>): <subject>

[optional body]
[optional footer]
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`.

Example: `feat(crawler): add support for multi-step login forms`

## Submitting a Pull Request

1. Fork the repository and create a feature branch from `main`:
   `git checkout -b feat/my-feature`
2. Make your changes, add tests, and ensure all checks pass locally.
3. Push the branch and open a PR against `main`.
4. Fill in the PR template completely.
5. Link any related issues using `Closes #<issue-number>`.

## Review Process

- At least one maintainer must approve before merging.
- All CI checks (lint, test, docker-build) must be green.
- Squash merge is used; the PR title becomes the commit message.
