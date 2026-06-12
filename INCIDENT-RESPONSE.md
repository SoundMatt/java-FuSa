# Incident Response Plan

**Standard:** IEC 62443-2-1 §4.3.4 / ISO 21434 §8.6

## 1. Scope

This plan covers security and safety incidents affecting java-FuSa and
projects that use it as a tool qualification artefact in their safety case.

## 2. Incident Classification

| Class | Description | Response SLA |
|-------|-------------|--------------|
| P1 – Critical | RCE, data exfiltration, supply-chain compromise | 4 h |
| P2 – High | Incorrect safety findings, false negatives in CYBER rules | 24 h |
| P3 – Medium | Performance degradation, partial rule failures | 72 h |
| P4 – Low | Documentation errors, cosmetic issues | 2 weeks |

## 3. Detection

Incidents may be detected via:

- Automated CI alerts (`.github/workflows/ci.yml`)
- User vulnerability reports (see `SECURITY.md`)
- Dependency vulnerability scanning (`jfusa vuln`)
- Tool qualification failures (`jfusa qualify`)

## 4. Response Procedure

### 4.1 Triage (0–4 h for P1/P2)

1. Assign incident owner
2. Reproduce and classify severity
3. Determine affected versions and users
4. Create private GitHub issue or security advisory

### 4.2 Containment

- Disable affected rule(s) via `.fusa.json` `rules.exclude` if they produce
  false safety assertions
- Communicate to known users if rule output is relied upon in safety cases
- Tag affected release as deprecated

### 4.3 Remediation

- Develop fix on private branch
- Add regression test to qualification suite (`jfusa qualify`)
- Re-run full evidence pipeline (`make evidence`)
- Bump patch version and tag release

### 4.4 Recovery

- Publish patched release with security advisory
- Distribute updated `qualify-report.json` for re-qualification
- Notify affected users via GitHub security advisory

### 4.5 Post-Incident Review

- Root cause analysis documented in `.fusa-problems.json` (`jfusa pr add`)
- Update TARA if threat model changes (`jfusa tara`)
- Update CHANGELOG.md

## 5. Contacts

| Role | Contact |
|------|---------|
| Security Lead | security@soundmatt.com |
| Maintainer | matt@jellybaby.com |

## 6. Evidence Trail

All incident handling is evidenced via:

- Problem reports: `jfusa pr`
- Qualification results: `jfusa qualify`
- TARA updates: `jfusa tara`
- Audit pack: `jfusa audit-pack`
