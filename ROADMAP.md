# Roadmap

## v0.2.0 — Static Analysis Expansion

- **LINT011–020**: Additional Java safety rules
  - Unchecked cast without annotation
  - `instanceof` without pattern variable
  - Mutable public fields
  - Static initialisers throwing exceptions
- **ANA007–010**: Extended analysis
  - Double-checked locking detection
  - `volatile` correctness
  - Lock ordering analysis
  - Resource leak in lambda
- **COMP001**: Improve cyclomatic complexity to handle lambda bodies
- `jfusa fix`: Auto-fix mode for LINT001, LINT007 (insert annotation / remove sysout)

## v0.3.0 — AI-Assisted Analysis

- `jfusa explain <finding-id>`: Natural language explanation of a finding
- LLM-powered remediation suggestions in HTML report
- `jfusa classify`: Auto-classify unclassified `//fusa:unsafe` annotations

## v0.4.0 — OSV/NVD Integration

- `jfusa vuln --online`: Live CVE lookup via OSV.dev REST API
- Scheduled vulnerability monitoring CI action
- Automatic SBOM dependency verification

## v0.5.0 — IDE Integration

- Language Server Protocol (LSP) server mode (`jfusa lsp`)
- VS Code extension for real-time finding annotations
- IntelliJ IDEA plugin

## v1.0.0 — Production Release

- Full x-FuSa spec v1.9 compliance verification
- Independent tool qualification certificate
- Signed release artifacts
- Maven Central publication
- Long-term support (LTS) commitment

## Backlog

- `jfusa compare`: Compare two projects' safety profiles
- `jfusa import`: Import findings from SpotBugs/PMD/Checkstyle XML
- `jfusa export`: Export to JIRA/Linear issue tracker
- Web UI dashboard (`jfusa serve`)
- AUTOSAR Adaptive Platform alignment
- Rust and Python bindings via FFI
