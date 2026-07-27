# java-FuSa — Java Functional Safety Tool Suite

[![CI](https://github.com/soundmatt/java-FuSa/actions/workflows/ci.yml/badge.svg)](https://github.com/soundmatt/java-FuSa/actions/workflows/ci.yml)
[![x-FuSa spec](https://img.shields.io/badge/x--FuSa%20spec-v1.10-blue)](https://github.com/soundmatt/x-FuSa)
[![Java 21](https://img.shields.io/badge/java-21-orange)](https://adoptium.net/)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-green)](LICENSE)

**jfusa** is the Java implementation of the [x-FuSa specification v1.10](https://github.com/soundmatt/x-FuSa) — a tool-qualification-grade functional safety CLI for Java projects targeting ISO 26262, IEC 61508, ISO 21434, DO-178C, IEC 62443, UN R.155, and SLSA.

It is feature-equivalent to [go-FuSa](https://github.com/soundmatt/go-FuSa) and [cpp-FuSa](https://github.com/soundmatt/cpp-FuSa).

## Features

- **45 commands** covering the full safety evidence pipeline
- **Zero runtime dependencies** — pure Java 21 stdlib
- **Self-qualifying** — `jfusa qualify` runs TC-001 through TC-010 and produces a signed `qualify-report.json`
- **50+ rules**: FUSA, LINT, ANA, CYBER, TRACE, COMP, COV, MISRA, SLSA, IEC62443, VULN
- **Standards**: ISO 26262, IEC 61508, ISO 21434, DO-178C, IEC 62443, UN R.155, SLSA L2/L3
- **Evidence artifacts**: SBOM (SPDX 2.3), SLSA provenance, SARIF, safety-case GSN, dFMEA, TARA, HARA, SCI, SAS

## Quick Start

```bash
# Build
mvn package

# Initialise a project
java -jar target/jfusa.jar init my-project

# Run all rules
java -jar target/jfusa.jar check

# Tool qualification (required for safety case)
java -jar target/jfusa.jar qualify

# Full evidence pipeline
make evidence
```

Or via Docker:

```bash
docker build -t soundmatt/jfusa .
docker run --rm -v $(pwd):/project soundmatt/jfusa check
```

## Installation

```bash
# Clone and build
git clone https://github.com/soundmatt/java-FuSa.git
cd java-FuSa
mvn package -DskipTests

# Install to PATH (macOS/Linux)
cp target/jfusa.jar ~/bin/
echo '#!/bin/sh\nexec java -jar ~/bin/jfusa.jar "$@"' > ~/bin/jfusa
chmod +x ~/bin/jfusa
```

## Commands

### Core

| Command | Description |
|---------|-------------|
| `jfusa init [name]` | Initialise `.fusa.json` and `.fusa-reqs.json` |
| `jfusa check` | Run all rules and report findings |
| `jfusa lint` | Run Java coding rules (LINT001–010) |
| `jfusa analyze` | Run static analysis rules (ANA001–006) |
| `jfusa cyber` | Run CWE-mapped security rules (CYBER001–020) |
| `jfusa report [file]` | Render or convert a saved report |
| `jfusa template <kind> [name]` | Generate safety plan, HARA, test evidence, qualification plan templates |

**Flags:** `--format=<text\|json\|html\|sarif>` `--output=<file>` `--fail-on-warn`

### Analysis & Evidence

| Command | Description |
|---------|-------------|
| `jfusa trace` | Requirement ↔ code traceability matrix (`//fusa:req` annotations) |
| `jfusa verify` | Generate `.fusa-evidence.json` |
| `jfusa release` | Generate SBOM (SPDX 2.3) + SLSA provenance |
| `jfusa qualify` | Run tool qualification suite (TC-001–TC-010) |
| `jfusa safety-case` | Generate GSN safety-case.{json,md,mermaid} |
| `jfusa fmea` | Generate dFMEA (fmea.{json,csv}) |
| `jfusa boundary` | Package dependency boundary graph |
| `jfusa coupling` | Data/control coupling report (DO-178C MC/DC) |
| `jfusa tara` | TARA per ISO 21434 Ch.9 |
| `jfusa hara` | HARA per ISO 26262-3 |
| `jfusa vuln` | Dependency vulnerability scan |
| `jfusa audit-pack` | Bundle all evidence artifacts into audit-pack.zip |
| `jfusa diff <a.json> <b.json>` | Compare two reports by fingerprint |
| `jfusa badge` | Generate SVG status badge |
| `jfusa impact [files...]` | Change impact analysis |

### Compliance

| Command | Description |
|---------|-------------|
| `jfusa do178 [--format=text\|json]` | DO-178C Annex A gap report (DAL A–D) |
| `jfusa iso26262 [--format=text\|json]` | ISO 26262 Part 6 gap report (ASIL A–D) |
| `jfusa iso21434 [--format=text\|json]` | ISO 21434 gap report (CAL 1–4) |
| `jfusa iec61508 [--format=text\|json]` | IEC 61508 gap report (SIL 1–4) |
| `jfusa iec62443` | IEC 62443 check (INCIDENT-RESPONSE.md) |
| `jfusa unece [--format=text\|json]` | UN R.155 Annex 5 threat categories |
| `jfusa slsa` | SLSA L2/L3 supply chain checks |
| `jfusa sas` | Software Accomplishment Summary (DO-178C §11.20) |
| `jfusa sci [--format=json\|markdown]` | Software Configuration Index (DO-178C §11.16) |
| `jfusa coverage` | Show JaCoCo coverage metrics |
| `jfusa comp` | Cyclomatic complexity analysis |
| `jfusa misra [--format=json\|text]` | MISRA Java 2023 alignment report |

### Management

| Command | Description |
|---------|-------------|
| `jfusa req list\|add <id> <title>` | Manage `.fusa-reqs.json` |
| `jfusa pr init\|list\|add\|close` | Problem report log (DO-178C §11.17) |
| `jfusa disposition list\|add <fp> <disp> <rationale>` | Manage finding dispositions |
| `jfusa metrics [record]` | Track safety metrics over time |
| `jfusa sign sign\|verify <file>` | HMAC-SHA256 file signing |
| `jfusa hooks install\|remove` | Git pre-commit hook |
| `jfusa fix` | Auto-fix findings (future) |

### Info

| Command | Description |
|---------|-------------|
| `jfusa capabilities` | List all registered rules with descriptions |
| `jfusa version` | Print version and spec |

## Configuration

`.fusa.json` (created by `jfusa init`):

```json
{
  "schema": "x-fusa-1.10",
  "project": {
    "name": "my-project",
    "version": "1.0.0",
    "standard": "ISO26262"
  },
  "rules": {
    "exclude": ["LINT007"],
    "severity": {
      "LINT010": "INFO"
    }
  },
  "report": {
    "format": "text",
    "output": ""
  }
}
```

**Standards:** `ISO26262`, `IEC61508`, `ISO21434`, `DO178C`, `generic`

## Annotation Syntax

Annotate Java source lines to suppress or link rules:

```java
return null; //fusa:unsafe intentionally null — documented in safety case

System.exit(1); //fusa:safe-state initiating shutdown sequence

//fusa:req REQ-AUTH-001 password must be validated before use
void authenticate(String pass) { ... }

//fusa:test TC-004 tests this branch
if (x > 0) { ... }

static volatile int counter; //fusa:shared updated by multiple threads (REQ-CONC-003)

private static void recurse(int n) { //fusa:recursive 10
    if (n > 0) recurse(n - 1);
}

Method m = cls.getMethod("foo"); //fusa:reflect needed for plugin architecture
```

## Rule Reference

### FUSA — Project Structure

| Rule | Severity | Description |
|------|----------|-------------|
| FUSA001 | ERROR | `.fusa.json` configuration file present |
| FUSA002 | ERROR | Java build file (`pom.xml` / `build.gradle`) present |
| FUSA003 | WARNING | `LICENSE` file present |
| FUSA004 | WARNING | `README.md` present |
| FUSA005 | WARNING | CI configuration present |

### LINT — Java Coding Rules

| Rule | Severity | Description |
|------|----------|-------------|
| LINT001 | WARNING | `return null` without `//fusa:unsafe` |
| LINT002 | ERROR | `System.exit()` without `//fusa:safe-state` |
| LINT003 | WARNING | `new Thread()` without `//fusa:unsafe` |
| LINT004 | WARNING | Static mutable field without `//fusa:shared` |
| LINT005 | ERROR | Float/double `==` comparison |
| LINT006 | WARNING | Recursive method without `//fusa:recursive <max>` |
| LINT007 | WARNING | `System.out/err.print*` in non-test code |
| LINT008 | WARNING | Reflection without `//fusa:reflect` |
| LINT009 | WARNING | `@SuppressWarnings("unchecked")` without `//fusa:unsafe` |
| LINT010 | INFO | `@Deprecated` annotation |

### ANA — Static Analysis

| Rule | Severity | Description |
|------|----------|-------------|
| ANA001 | WARNING | Chained method call without null check |
| ANA002 | WARNING | Resource allocated outside try-with-resources |
| ANA003 | ERROR | `synchronized` on non-final field |
| ANA004 | ERROR | `InterruptedException` caught without `Thread.currentThread().interrupt()` |
| ANA005 | WARNING | Empty `catch` block |
| ANA006 | WARNING | Exception thrown without cause chain |

### CYBER — Security (CWE-mapped)

| Rule | Severity | CWE | Description |
|------|----------|-----|-------------|
| CYBER001 | ERROR | CWE-89 | SQL string concatenation (injection) |
| CYBER002 | ERROR | CWE-78 | Command injection via `exec()`/`Runtime` |
| CYBER003 | WARNING | CWE-79 | XSS — unescaped output |
| CYBER004 | ERROR | CWE-22 | Path traversal — unvalidated `..` |
| CYBER005 | ERROR | CWE-259 | Hardcoded password constant |
| CYBER006 | ERROR | CWE-321 | Hardcoded cryptographic key |
| CYBER007 | ERROR | CWE-330 | `java.util.Random` in security context |
| CYBER008 | ERROR | CWE-326 | Weak cipher (DES, RC4, etc.) |
| CYBER009 | ERROR | CWE-327 | Broken hash (MD5, SHA-1) |
| CYBER010 | WARNING | CWE-614 | Insecure cookie (missing `Secure`) |
| CYBER011 | ERROR | CWE-611 | XXE — XML external entity |
| CYBER012 | ERROR | CWE-502 | Unsafe deserialization |
| CYBER013 | ERROR | CWE-918 | SSRF — server-side request forgery |
| CYBER014 | WARNING | CWE-117 | Log injection |
| CYBER015 | WARNING | CWE-190 | Integer overflow |
| CYBER016 | WARNING | CWE-209 | Information exposure in exception |
| CYBER017 | WARNING | CWE-352 | Missing CSRF token |
| CYBER018 | WARNING | CWE-400 | ReDoS — potentially catastrophic regex |
| CYBER019 | WARNING | CWE-770 | Resource exhaustion — unbounded allocation |
| CYBER020 | WARNING | — | SECURITY.md present |

## Evidence Artifacts

| File | Generated by | Description |
|------|-------------|-------------|
| `fusa-report.json` | `jfusa check --format=json` | Full findings report |
| `qualify-report.json` | `jfusa qualify` | Tool qualification report (TC-001–TC-010) |
| `sbom.json` | `jfusa release` | SPDX 2.3 Software Bill of Materials |
| `provenance.json` | `jfusa release` | SLSA in-toto provenance |
| `.fusa-evidence.json` | `jfusa verify` | Evidence manifest |
| `tara.json` + `tara.md` | `jfusa tara` | TARA (ISO 21434 Ch.9) |
| `fmea.json` + `fmea.csv` | `jfusa fmea` | dFMEA |
| `safety-case.json/md/mermaid` | `jfusa safety-case` | GSN safety case |
| `.fusa-hara.json` | `jfusa hara` | HARA (ISO 26262-3) |
| `sci.json` | `jfusa sci` | Software Configuration Index (DO-178C §11.16) |
| `sas.md` | `jfusa sas` | Software Accomplishment Summary (DO-178C §11.20) |
| `audit-pack.zip` | `jfusa audit-pack` | All artifacts bundled |

## Docker

```bash
# Build
docker build -t soundmatt/jfusa .

# Run single command
docker run --rm -v $(pwd):/project soundmatt/jfusa check

# Full evidence pipeline
docker compose run pipeline
```

## Runtime Safety Patterns

java-FuSa includes production-ready runtime safety primitives:

```java
// Software watchdog — kicks must arrive within timeout
Watchdog wd = new Watchdog("main", Duration.ofSeconds(10), () -> safeShutdown());
wd.start();
// In your main loop:
wd.kick();

// Heartbeat
Heartbeat hb = new Heartbeat("sensor", Duration.ofSeconds(1), () -> readSensor());
hb.start();

// Safe state guard — idempotent entry with registered handlers
SafeStateGuard guard = new SafeStateGuard("brake");
guard.onEnter(() -> applyEmergencyBrake());
guard.enter("sensor timeout");
```

## Standards Coverage

| Standard | Command | Coverage |
|----------|---------|---------|
| ISO 26262:2018 | `jfusa iso26262` | Parts 1–6, ASIL A–D |
| IEC 61508:2010 | `jfusa iec61508` | Parts 1–3, SIL 1–4 |
| ISO 21434:2021 | `jfusa iso21434` | CAL 1–4 |
| DO-178C | `jfusa do178` | DAL A–D, Tables A-1 to A-11 |
| IEC 62443 | `jfusa iec62443` | Incident response |
| UN R.155 | `jfusa unece` | Annex 5, TC-1 to TC-9 |
| SLSA | `jfusa slsa` | Level 2 / Level 3 |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Mozilla Public License 2.0 — see [LICENSE](LICENSE).

## Related Projects

- [go-FuSa](https://github.com/soundmatt/go-FuSa) — Go implementation (reference)
- [cpp-FuSa](https://github.com/soundmatt/cpp-FuSa) — C++ implementation
- [x-FuSa](https://github.com/soundmatt/x-FuSa) — Specification
