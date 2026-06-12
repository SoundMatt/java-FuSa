# CLAUDE.md — java-FuSa

Autonomous operation guide for Claude Code sessions on this project.

## Project Identity

- **Binary**: `jfusa` (fat-JAR at `target/jfusa.jar`)
- **Package**: `com.soundmatt.jfusa`
- **Spec**: x-FuSa v1.10
- **Language**: Java 21, Maven 3.9+, zero runtime dependencies
- **License**: MPL-2.0

## Quick Commands

```bash
mvn package -DskipTests     # Build fat-JAR
mvn test                     # Run JUnit 5 tests
java -jar target/jfusa.jar check   # Run all rules on this project
make evidence                # Generate all evidence artifacts
make qualify                 # Tool qualification suite
```

## Architecture

```
src/main/java/com/soundmatt/jfusa/
├── FuSa.java               # Core types (Finding, Severity, Category, fingerprint)
├── internal/Json.java      # Zero-dependency JSON encoder + recursive-descent parser
├── config/Config.java      # .fusa.json load/save/validate
├── engine/
│   ├── Rule.java           # Rule interface: id(), description(), run()
│   ├── Registry.java       # Thread-safe rule registry
│   └── Engine.java         # Execution engine + FUSA001-005 built-in rules
├── lint/LintRules.java     # LINT001-010 (Java coding)
├── analyze/AnalyzeRules.java # ANA001-006 (static analysis)
├── cyber/CyberRules.java   # CYBER001-020 (CWE-mapped security)
├── report/
│   ├── Report.java         # render(format) dispatcher
│   ├── TextRenderer.java   # Coloured/plain text + NO_COLOR support
│   ├── JsonRenderer.java   # x-FuSa §8 JSON schema
│   ├── HtmlRenderer.java   # Inline CSS HTML
│   └── SarifRenderer.java  # SARIF 2.1.0
├── trace/Trace.java        # Req traceability + TRACE001 rule
├── verify/Verify.java      # .fusa-evidence.json + VERIFY001 rule
├── release/Release.java    # SBOM/SLSA + RELEASE001-002 rules
├── qualify/Qualify.java    # TC-001 through TC-010 + QUALIFY001 rule
├── runtime/
│   ├── Watchdog.java       # Software watchdog with kick()
│   ├── Heartbeat.java      # Periodic heartbeat
│   └── SafeStateGuard.java # Idempotent safe-state entry
├── [domain]/               # safety-case, fmea, tara, hara, boundary,
│                           #   slsa, iec62443, iso26262, iec61508, iso21434,
│                           #   do178, unece, coverage, comp, misra, vuln,
│                           #   coupling, sas, sci, pr, impact, diff, badge,
│                           #   sign, hooks, disposition, metrics, template
└── cmd/Main.java           # CLI dispatcher — all 45 commands
```

## Key Invariants

### Zero Dependencies
Never add `<dependency>` entries without `<scope>test</scope>` or unless
they are part of the Maven build toolchain. Runtime code is stdlib-only.

### Rule Registration
Rules use `static {}` initializers to register into `Engine.DEFAULT`. Every
rule package with a `static {}` block also has a no-op `activate()` method.
`Main.java` calls `activate()` on every rule package in its own `static {}`
to force class loading.

### Fingerprint Stability
`FuSa.computeFingerprint` hashes `ruleId + \x1f + file + \x1f + normalizedMessage`.
Line number is intentionally excluded — fingerprints survive code reformatting.
`normalizeMessage` replaces digit runs with `#` to survive count changes.

### Exit Codes
- `0` — all rules passed
- `1` — gate failed (findings exceeded threshold)
- `2` — usage error (unknown command, missing flag)
- `3` — runtime error (no config, IO failure)

### Annotation Syntax (x-FuSa §6)
- `//fusa:req REQ-XXX`     — links line to requirement
- `//fusa:test TC-XXX`     — marks test for TC
- `//fusa:unsafe <reason>` — acknowledges LINT001/LINT009 finding
- `//fusa:safe-state <r>`  — acknowledges LINT002 (System.exit)
- `//fusa:recursive <n>`   — max recursion depth for LINT006
- `//fusa:shared <r>`      — acknowledges LINT004 (static mutable)
- `//fusa:reflect <r>`     — acknowledges LINT008 (reflection)

## Workflow for New Rules

1. Add `static final class RuleXXXXnnn implements Rule { ... }` in the
   appropriate package class
2. Register in that class's `static {}` block
3. Ensure `activate()` exists (even as no-op) and is called from `Main.java`
4. Write test in the corresponding `*Test.java`
5. Add rule ID to CHANGELOG.md and README.md

## Permissions

This project has pre-approved permissions in `.claude/settings.local.json`.
All build, file, git, Docker, and Java commands are pre-approved.

## Do Not

- Add runtime dependencies to `pom.xml`
- Use `@SuppressWarnings("unchecked")` without a `//fusa:unsafe` annotation
- Call `System.exit()` except in `Main.java` (and with `//fusa:safe-state`)
- Print to stdout in rule implementations (only in CLI handlers)
- Catch `Throwable` or `Error`
