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
  ssrf/
    internal_urls.txt   - Internal/loopback URLs (127.0.0.1, file://, gopher://)
    cloud_metadata.txt  - AWS/GCP/Azure/Alibaba metadata service endpoints
  xxe/
    entities.txt        - External entity declarations (file://, http://, parameter entities)
  deserialization/
    malformed.txt       - Malformed Java/PHP/Python/.NET serialized blobs
  path_traversal/
    unix.txt            - ../ traversal payloads targeting /etc/passwd, /etc/hosts, etc.
    windows.txt         - ..\ traversal payloads targeting win.ini, boot.ini, etc.
  open_redirect/
    urls.txt            - External-redirect probe URLs pointing at the canary domain
```

## Usage

The `PayloadLoader` class in `src/fuzzing/payload_loader.py` reads these files
automatically at fuzzing time.  Comment lines (starting with `#`) and blank lines
are ignored.  Duplicates are removed.

How many payloads run, and which scanner classes are active, is controlled
from the CLI:

- `--max-payloads-per-vector` (env `MAX_PAYLOADS_PER_VECTOR`, default `50`) —
  cap on how many payloads are sent per (vector × scanner). Dominant lever
  for both runtime cost and intrusiveness.
- `--payload-types` (env `PAYLOAD_TYPES`, default = full CSV of all eight
  classes) — enables or disables entire scanner classes from this directory
  (e.g. `--payload-types sqli,xss` to skip the other six).

Speed knobs (`--concurrent-vectors`, `--concurrent-payloads`,
`--requests-per-second`) change *how fast* the payloads in this directory are
sent, not *which* payloads are sent. See the README at the repo root for the
full split between speed and coverage flags.
