---
name: Bug Report
about: Report a reproducible problem with the DAST framework
title: "[BUG] "
labels: bug
assignees: ''
---

## Description

A clear and concise description of the bug.

## Steps to Reproduce

1. ...
2. ...
3. ...

## Expected Behaviour

What you expected to happen.

## Actual Behaviour

What actually happened. Include the full error message and stack trace if available.

## Environment

- DAST git commit hash:
- Host OS:
- Docker version:
- docker compose version:
- Target application and version (e.g. DVWA 2.3):
- Tuning parameters used (--concurrent-vectors, --concurrent-payloads, --requests-per-second, --depth, --max-pages, --max-payloads-per-vector, --payload-types, --request-timeout):

## Logs

Paste the relevant portion of `reports/<scan_id>/scan.log` here, or attach the file.

```
(paste log output here)
```

## Additional Context

Any other context about the problem (screenshots of the report, network traces, etc.).
