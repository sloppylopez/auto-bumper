# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open public GitHub issues for security bugs in this tool or in how it handles advisories.**

Email or open a **private** security advisory on GitHub if you have repo access:

- Repository: https://github.com/sloppylopez/auto-bumper
- Use **Security → Report a vulnerability** when available

Include:

1. Steps to reproduce
2. Impact (data exposure, arbitrary file write, etc.)
3. Affected version

We aim to acknowledge within 7 days and ship a fix or mitigation as soon as practical.

## Scope

- Vulnerabilities in **auto-bumper itself** (CLI, editors, cache handling)
- Incorrect remediation that could weaken a consumer project

Out of scope: vulnerabilities in third-party dependencies discovered by the scanner — report those to the upstream project or OSV.
