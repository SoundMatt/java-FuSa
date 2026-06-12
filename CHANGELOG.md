# Changelog

All notable changes to java-FuSa are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.1.0] — 2026-06-12

### Added

- Initial release of java-FuSa, the Java implementation of the x-FuSa spec v1.9
- **45 CLI commands** matching go-FuSa feature parity:
  `init`, `check`, `lint`, `analyze`, `cyber`, `report`, `template`,
  `trace`, `verify`, `release`, `qualify`, `safety-case`, `fmea`,
  `boundary`, `coupling`, `tara`, `hara`, `vuln`, `audit-pack`, `diff`,
  `badge`, `req`, `fix`, `hooks`, `sign`, `do178`, `iso21434`, `iso26262`,
  `iec61508`, `iec62443`, `unece`, `slsa`, `sas`, `sci`, `coverage`,
  `comp`, `pr`, `disposition`, `impact`, `metrics`, `misra`,
  `capabilities`, `version`
- **FUSA001–005** project structure rules
- **LINT001–010** Java coding rules (return null, System.exit, raw threads,
  static mutable state, float equality, recursion, System.out, reflection,
  @SuppressWarnings, @Deprecated)
- **ANA001–006** static analysis rules (chained calls, resource leaks,
  synchronized on non-final, InterruptedException, empty catch, exception chaining)
- **CYBER001–020** CWE-mapped security rules covering SQL injection,
  command injection, XSS, path traversal, hardcoded credentials, weak
  random, weak cipher, broken hash, insecure cookie, XXE, deserialization,
  SSRF, log injection, integer overflow, info exposure, CSRF, ReDoS,
  resource exhaustion, SECURITY.md presence
- **TRACE001** requirement traceability matrix (`//fusa:req` annotations)
- **VERIFY001** evidence artifact generation
- **RELEASE001–002** SBOM (SPDX 2.3) and SLSA provenance generation
- **QUALIFY001** tool qualification suite (TC-001 through TC-010)
- **SLSA001–003** supply chain security rules
- **IEC62443-001** incident response document check
- **COV001** JaCoCo coverage gate
- **COMP001** cyclomatic complexity gate
- **MISRA001** MISRA Java 2023 alignment
- **VULN001** dependency vulnerability scan hint
- ISO 26262 ASIL A–D gap report (`jfusa iso26262`)
- IEC 61508 SIL 1–4 gap report (`jfusa iec61508`)
- ISO 21434 CAL 1–4 gap report (`jfusa iso21434`)
- DO-178C DAL A–D gap report with Tables A-1 through A-11 (`jfusa do178`)
- UN R.155 Annex 5 threat categories TC-1 to TC-9 (`jfusa unece`)
- TARA per ISO 21434 Chapter 9 (`jfusa tara`)
- HARA per ISO 26262-3 (`jfusa hara`)
- dFMEA derived from public method signatures (`jfusa fmea`)
- GSN safety-case diagram in JSON/Markdown/Mermaid (`jfusa safety-case`)
- Software Accomplishment Summary DO-178C §11.20 (`jfusa sas`)
- Software Configuration Index DO-178C §11.16 (`jfusa sci`)
- Package boundary graph in Mermaid/DOT (`jfusa boundary`)
- Data/control coupling analysis DO-178C MC/DC (`jfusa coupling`)
- SBOM in SPDX 2.3 format (`jfusa release`)
- SLSA in-toto provenance (`jfusa release`)
- Finding diff by fingerprint (`jfusa diff`)
- SVG badge generation (`jfusa badge`)
- HMAC-SHA256 file signing/verification (`jfusa sign`)
- Git pre-commit hook install/remove (`jfusa hooks`)
- Finding dispositions CRUD (`jfusa disposition`)
- Safety metrics history tracking (`jfusa metrics`)
- Problem report log DO-178C §11.17 (`jfusa pr`)
- Change impact analysis (`jfusa impact`)
- Runtime safety patterns: `Watchdog`, `Heartbeat`, `SafeStateGuard`
- Zero runtime dependencies (Java stdlib only)
- Multi-stage Docker build (`eclipse-temurin:21-jre-alpine`)
- Maven fat-JAR via `maven-shade-plugin`
- GitHub Actions CI matrix (Java 21, ubuntu/macos)
- JaCoCo code coverage reporting
- Tool self-qualification via `jfusa qualify`
- Full documentation suite: README, CLAUDE.md, CONTRIBUTING.md,
  SECURITY.md, INCIDENT-RESPONSE.md, ROADMAP.md, docs/

[0.1.0]: https://github.com/soundmatt/java-FuSa/releases/tag/v0.1.0
