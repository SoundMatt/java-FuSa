# Tool Safety Manual

**Tool:** jfusa v0.1.0
**Spec:** x-FuSa v1.15
**Date:** 2026-06-12

## Purpose

This manual describes the safe use of jfusa as a tool qualification artefact
within safety-critical software development processes.

## Scope of Use

jfusa is intended for:

1. Static analysis of Java source code for safety and security rule violations
2. Generation of evidence artefacts required by ISO 26262, IEC 61508, DO-178C, ISO 21434
3. Tool qualification per DO-178C §12 / ISO 26262-8:11

## Assumptions of Use

1. **Java 21+**: jfusa requires Java 21 or later. Earlier versions are unsupported.
2. **Source access**: jfusa must have read access to the project source tree.
3. **Standard Maven layout**: Rules assume `src/main/java/` for production code
   and `src/test/java/` for test code.
4. **Accurate configuration**: `.fusa.json` must correctly specify the applicable
   standard (`ISO26262`, `IEC61508`, etc.) for correct gap-report thresholds.
5. **Human review required**: jfusa findings are advisory. Final safety judgements
   must be made by qualified safety engineers.

## Limitations

- **No data-flow analysis**: LINT/ANA rules use pattern matching, not full AST analysis.
  Some findings may be false positives; suppress with `//fusa:unsafe` and document rationale.
- **No inter-procedural analysis**: Cyclomatic complexity (COMP001) is intra-method only.
- **Offline vulnerability database**: VULN rule uses a minimal embedded list; use `--online`
  (future feature) for comprehensive CVE checking.
- **No binary analysis**: jfusa analyses source code only, not compiled bytecode.

## Error Modes and Effects

| Error Mode | Effect | Detection | Mitigation |
|------------|--------|-----------|------------|
| Rule throws exception | Rule skipped, error logged | Engine.Result.errors() | Re-run after fix |
| Config parse failure | All rules skipped | EXIT_RUNTIME | Fix .fusa.json |
| Missing .fusa.json | Rules run with defaults | FUSA001 finding | Run jfusa init |
| SHA-256 collision | Incorrect fingerprint dedup | Probability ~2^-128 | Negligible risk |

## Qualified Configuration

The tool was qualified under the following configuration:

- Java: 21 (Eclipse Temurin)
- OS: Linux (ubuntu-latest), macOS (macos-latest)
- Maven: 3.9
- JUnit: 5.10

Any deviation from this configuration requires re-qualification.

## Evidence Trail

| Artefact | Command | Standard |
|----------|---------|---------|
| `qualify-report.json` | `jfusa qualify` | DO-178C §11.14, §12 |
| `sbom.json` | `jfusa release` | SLSA L2 |
| `provenance.json` | `jfusa release` | SLSA L2 |
| `.fusa-evidence.json` | `jfusa verify` | x-FuSa §7 |
| `audit-pack.zip` | `jfusa audit-pack` | ISO 26262-8 |

## Change Control

Changes to jfusa itself must:

1. Pass `mvn test`
2. Pass `make qualify` (TC-001 through TC-010)
3. Pass `make vet` (jfusa checks its own source)
4. Update CHANGELOG.md
5. Increment version in `pom.xml` and `FuSa.VERSION`
