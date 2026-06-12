# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not report security vulnerabilities in public GitHub issues.**

Please report vulnerabilities by emailing **security@soundmatt.com** with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact assessment
4. Any suggested mitigations

We will acknowledge receipt within **48 hours** and aim to provide a
remediation plan within **14 days** for critical issues.

## Disclosure Policy

- We follow **coordinated disclosure**: vulnerabilities are kept confidential
  until a patch is available.
- Once patched, we will publish a security advisory in the repository.
- We credit reporters in the advisory unless anonymity is requested.

## Security Standards

java-FuSa implements security rules aligned with:

- **ISO 21434** — Cybersecurity for road vehicles
- **IEC 62443** — Industrial automation and control systems security
- **OWASP Top 10** — Common web application vulnerabilities
- **CWE/CVE** — CYBER001–020 rules map to CWE identifiers

## Tool Security

As a static analysis tool, jfusa:

- Reads source files and configuration only — it never modifies source code
- Makes no network calls (offline-capable by design)
- Produces evidence artifacts in the project directory
- Signs artifacts with HMAC-SHA256 (`jfusa sign`)

## Signing

Evidence artifacts can be cryptographically signed and verified:

```
jfusa sign sign qualify-report.json
jfusa sign verify qualify-report.json
```
