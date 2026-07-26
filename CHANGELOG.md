# Changelog

All notable changes to java-FuSa are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## v0.4.1 — 2026-07-26

### Fixed

- **P1 test-coverage**: Added `VerifyTest.java` with three tests for `Verify.saveEvidence()`
  and `RuleEvidencePresent` (file-absent WARNING, file-present empty), all annotated
  `//fusa:test REQ-VERIFY001`. Resolves zero traceability coverage for REQ-VERIFY001.

- **P1 requirements**: Added three missing entries to `.fusa-reqs.json`:
  `REQ-QUALIFY001` (qualify-report.json must be present), `REQ-VERIFY001`
  (.fusa-evidence.json must be present), `REQ-TRACE001` (all annotated requirements must
  have test coverage). All three were referenced by `//fusa:req` annotations but
  unregistered, causing metadata-less entries in the trace matrix.

- **P2 test-coverage**: Added `//fusa:test REQ-QUALIFY001` annotation before each of the
  three `@Test` methods in `QualifyTest.java` that exercise the QUALIFY001 rule
  (`qualify_generatesReport`, `qualify_reportContainsPassStatus`,
  `qualify_reportHasIntegrityHash`), following the one-ID-per-line convention.

- **P2 correctness**: Changed `Makefile` build target and `.github/workflows/ci.yml` Build
  step from `mvn -q package -DskipTests` to `mvn -q clean package -DskipTests` to prevent
  JaCoCo report failure from stale class files after incremental Disposition.java edits.

- **P2 test-coverage**: Added JaCoCo `<check>` execution to `pom.xml` with
  `INSTRUCTION` minimum `0.70`. Added `MainTest.java` (78 tests) covering CLI dispatch
  paths for all 45 sub-commands including `--mcdc-file`, `--strict-hlr-llr`,
  `--qualification-method`, `--independent-reviewer`, and standards adapter commands.
  Instruction coverage now 81% / line coverage 83% (up from 51%/54%).

### Changed

- Version bumped to `0.4.1` in `FuSa.java` and `pom.xml`.
- Test suite expanded from 160 to 238 tests across 18 test classes.

---

## v0.4.0 — 2026-07-26

### Added

- **#11 HLR/LLR Decomposition**: `Trace` now supports `parent_id` on requirements in
  `.fusa-reqs.json`. `Trace.loadFullRequirements()` reads the full hierarchy.
  `Trace.validateHierarchy()` checks that every LLR references an existing HLR and
  every HLR has at least one LLR child. `--strict-hlr-llr` CLI flag forces error
  regardless of DAL; high-integrity (DAL-A/B, ASIL-D) also fail hard. Text and JSON
  renderers include a `hierarchy` section with violations listed.

- **#12 Tool Qualification Display**: `Qualify` command now accepts
  `--qualification-method` (`self`/`independent`), `--qualifier`, and `--record-uri`
  flags. `qualify-report.json` emits `qualificationMethod`, `qualificationBadge`
  (`independently-qualified` / `self-qualified` / `unqualified`),
  `qualificationRecordUri`, and `qualifierIdentity`. Badge is shown in console output.

- **#13 MC/DC Coverage**: `Coverage.parseMcdc()` reads LLVM coverage JSON export
  (`mcdc_records[].conditions[].covered_true_count` / `covered_false_count`).
  A condition is MC/DC covered only when both counts are > 0. `coverage --mcdc`
  `--mcdc-file` flag gates on any function with uncovered conditions (hard fail).
  Structured `McdcReport` result type exposed for programmatic use.

- **#14 V&V Independence**: `Qualify` command accepts `--implementation-author`,
  `--independent-reviewer`, `--independent-test-executor`, and `--achievable-asil`
  flags. `qualify-report.json` emits those fields plus `independenceStatus`
  (`"independent"` when reviewer differs from author, else `"not-independent"`).

### Changed

- Version constant in `FuSa.java` corrected to `0.4.0` (was `0.3.0`; pom.xml was
  already tracking patch releases, now both sources are in sync).
- 26 new tests added (157 total across 17 test classes).

---

## v0.3.1 — 2026-07-25

- Add docker-publish.yml — publish ghcr.io/soundmatt/java-fusa on tag push
- First tagged release

---

## [0.3.0] — 2026-06-13

### Fixed

- **#6 §2.6 MUST**: `--no-color` CLI flag now honoured in addition to `NO_COLOR` env var.
  The flag is detected globally (before subcommand dispatch) and applies to all text output.
- **#5 §3.2 MUST**: `projectRoot` field added to JSON check/lint/analyze/cyber reports.
  Value is the absolute path of the project root (`--dir` value). Required by FuSaOps
  `fusaops diff --baseline` for path re-rooting in polyglot diffs.
- **#3 §9.1/§2.4.1**: `capabilities.standards[]` now emits `"iec62443"` (was `"iec62443-4-1"`),
  consistent with the `iec62443` gap-report `standard` field and all other x-FuSa tool implementations.

### Added

- **#4 §5 SHOULD**: `trace --format json` `requirements[]` entries now include `title` and
  `standard` fields when available in `.fusa-reqs.json`. Entries without metadata still emit
  only `id` (backward compatible). Enables FuSaOps requirement-browser enrichment.

### Changed

- Spec version updated to x-FuSa 1.10.4.
- 6 new §11 conformance tests added (131 total).

---

## [0.2.0] — 2026-06-12

### Fixed

- All §11 conformance gaps from v0.1.0 verified and closed
- `normalizeMessage` space-before-# bug
- `hasWarnings()` incorrectly counted ERROR findings
- LINT007 test-file exclusion matched filenames instead of directories
- ANA001 regex broadened; ANA005 single-line catch detection added
- CYBER001 regex extended to cover raw SQL string literal concatenation
- Audit-pack duplicate `artifact-manifest.json` ZIP entry causing exit 3

### Added

- `Spec11ConformanceTest.java` — 25 new §11 conformance tests (98 → 125 total)
- Sign command arg order standardised to `(artifact, keyFile)`

### Changed

- Spec version updated to x-FuSa 1.10
- Dockerfile updated to `eclipse-temurin:21-jre-alpine`, OCI labels corrected
- `trace --format json` emits canonical §5 shape with `kind:"trace-matrix"`,
  `tags[].kind` values `impl`/`test`/`sec-test`, and `secTestedRequirements` in coverage

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
