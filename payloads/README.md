# Payloads Directory

This directory contains attack payloads organized by vulnerability type.
All payloads are sourced from SecLists and PayloadsAllTheThings.

## Structure

```
payloads/
  sqli/
    error_based.txt     - Payloads that trigger database error messages
    blind_boolean.txt   - Boolean-condition payloads for blind detection
    time_based.txt      - Time-delay payloads (SLEEP, WAITFOR DELAY, pg_sleep)
    union_based.txt     - UNION SELECT payloads for data extraction
  xss/
    reflected.txt       - Standard reflected XSS payloads
    stored.txt          - Payloads suitable for stored XSS testing
    dom_based.txt       - javascript: URI and fragment-based payloads
    bypass_filters.txt  - Case variations and encoding tricks for WAF bypass
  cmdi/
    unix.txt            - Unix/Linux command injection (; id, | whoami, etc.)
    windows.txt         - Windows command injection (& whoami, | ver, etc.)
    blind.txt           - Time-based blind CMDi (sleep, ping)
```

## Usage

The `PayloadLoader` class in `src/fuzzing/payload_loader.py` reads these files
automatically at fuzzing time.  Comment lines (starting with `#`) and blank lines
are ignored.  Duplicates are removed.  The `max_payloads_per_vector` setting in
each scan profile controls how many payloads are used per injection point.
