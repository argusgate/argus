# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Use [GitHub Security Advisories](https://github.com/argusgate/argus/security/advisories/new) to report privately. You will receive a response within 72 hours.

Please include:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- The affected version(s)

We will coordinate a fix and disclosure timeline with you. Credit will be given in the release notes unless you prefer to remain anonymous.

## Scope

Vulnerabilities of interest include:

- Archive extraction bypasses (zip-slip, path traversal)
- Scanner rule bypasses that allow malicious code to pass undetected
- Denial-of-service via crafted archives or source files
- Any behaviour that allows code execution outside the scanned package
