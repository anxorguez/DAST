# Security Policy

## Supported Versions

Only the latest commit on the `main` branch is actively maintained and receives
security fixes.

| Version  | Supported |
|----------|-----------|
| main     | Yes       |
| older    | No        |

## Reporting a Vulnerability

**Do not open a public GitHub issue to report a security vulnerability in this project.**

If you discover a security vulnerability in the DAST framework itself (for example, a flaw
that could allow an attacker to escape the intended containerised scanning environment, read
arbitrary files from the host, or execute code outside the container), please report it
through GitHub's private Security Advisory mechanism:

1. Go to the repository on GitHub.
2. Click the **Security** tab.
3. Click **Report a vulnerability** under "Advisories".
4. Fill in the advisory form with as much detail as possible:
   - A clear description of the vulnerability.
   - Steps to reproduce or a proof-of-concept.
   - The potential impact and affected components.
   - Any suggested mitigations if known.

## Response SLA

- **Acknowledgement:** within 72 hours of receiving the report.
- **Initial assessment:** within 14 days.
- **Resolution or public disclosure plan:** within 90 days of initial report.

All valid security reports will be credited in the release notes unless the reporter
requests anonymity.

## Scope

The following are **in scope** for security reports:

- Vulnerabilities in the Python source code under `src/`.
- Container escape or privilege escalation in the Docker setup.
- Unsafe handling of attacker-controlled input in scan targets.

The following are **out of scope**:

- Vulnerabilities in DVWA or other third-party scan targets (report those upstream).
- Theoretical vulnerabilities without a realistic attack scenario.
- Issues in development dependencies not shipped in `requirements.txt`.

## Responsible Use

This tool is designed exclusively for authorised security testing. The maintainers accept
no liability for unauthorised use. See [LICENSE](LICENSE) for the full disclaimer.
