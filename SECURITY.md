# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities to **security@opensin-code.org**.

We aim to:
- Acknowledge receipt within 48 hours
- Provide initial assessment within 5 business days
- Release a fix within 30 days for critical issues

## Disclosure Process

1. **Private disclosure** — Email details to security@opensin-code.org
2. **Verification** — We confirm and assess the impact
3. **Fix development** — We develop and test a fix
4. **Coordinated release** — We publish the fix and advisory simultaneously

## Scope

This policy covers:
- SIN-Code-Security-Bundle core (cmd/, internal/, pkg/)
- All CLI tools and MCP integrations
- Dependencies managed via go.mod

Out of scope:
- Third-party integrations not maintained by OpenSIN-Code
- Issues in underlying Go standard library (report to Go team)

## Recognition

We credit reporters in our security advisories (with permission).
