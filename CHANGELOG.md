# Changelog

All notable changes to java-FuSa are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

## v0.6.2 — 2026-07-29

Patch release tracking the x-FuSa spec's two latest PATCH releases.

- Bumped `SPEC_VERSION` to 1.15.2 — the 1.15.1/1.15.2 spec revisions were
  pure documentation clarifications (schemaVersion/specVersion format, an
  explicit Rule A false-positive example) with no required behavior or
  wire-format change.
- Synced the same `SPEC_VERSION` value into the `Dockerfile`, `ci.yml`,
  and `docker-publish.yml` build-args, which had been missed in the
  initial bump and would otherwise have kept labelling the published
  container image as spec `1.15.0`.

## v0.6.1 — 2026-07-29

Patch release fixing nine real defects found by a same-day deep audit that
built `jfusa`, ran every command against this repo, and diffed output
against the x-FuSa spec line-by-line (SoundMatt/java-FuSa#38–#46).

### Fixed

- **`--dir` was a no-op** (#38): nothing parsed it, so every command
  silently operated on cwd regardless of the flag. `main()` now resolves
  `root` from `--dir` (both `--dir value` and `--dir=value` forms) before
  dispatch.
- **`report` echoed a cached file instead of re-running analysis** (#39):
  contradicted the §9.1 MUST that `report` behaves like `check` (same
  Finding[]/summary shape, never gate-fails). Reimplemented to run
  `Engine.DEFAULT` directly, honour `--output` per §2.2, and treat
  `--strict` as a usage error.
- **`audit-pack` omitted several generated evidence files** (#40):
  `comp-report.json`, `vuln.json`, `coupling-report.json`, `sci.json`,
  `sas.{json,md}`, and three of the seven standards gap-reports were
  missing from the hardcoded artifact list, while non-spec `CHANGELOG.md`/
  `SECURITY.md` were bundled. The list now references each artifact's own
  filename constant and drops the two non-spec files.
- **`iso26262` doubled the `ASIL-` prefix** (#41): the default `--asil`
  value (`"ASIL-B"`) was concatenated with an already-added `ASIL-`
  prefix, producing `"ASIL-ASIL-B"` in `level` and both gap notes.
- **Structured `error.code` used underscores** (#42): `no_config`/
  `invalid_config` instead of the spec's hyphenated `no-config`/
  `invalid-config` enum.
- **`misra --format json` used a bespoke shape** (#43): `kind:
  "misra-report"` with a flat `{totalFindings, findings}` body instead of
  the canonical `gap-report` schema every sibling standards command uses.
  Now emits `objectives[]`/`summary` and writes
  `misra-java-gap-report.json`.
- **`Finding.standard` emitted display strings, not canonical ids** (#44):
  `"IEC 61508-3"`, `"ISO 21434"`, `"MISRA Java"`/`"MISRA Java 2023"`,
  `"SLSA"` (inconsistent with the lowercase `"slsa"` used elsewhere), and
  CWE ids (`"CWE-89"`, ...) used as the standard value itself. Replaced
  with the matching §2.4.1 canonical lowercase id at every call site.
- **`iec62443` used the non-canonical id `"iec62443"`** (#45): the bare
  command name isn't a registry id — both the gap-report `standard` field
  and `capabilities.standards[]` now emit `"iec62443-4-1"`.
- **`qualify --format json --output <file>` also echoed to stdout**
  (#46): violated §2.2's "MUST NOT also write it to stdout" — the same
  document was both written to the file and printed. `cmdQualify` now
  defaults `--output` to empty (like `check`/`trace`/`report`) so
  `Qualify.run` can tell an explicit `--output` apart from the default
  path and suppress the stdout echo accordingly.

## v0.6.0 — 2026-07-28

Adopts x-FuSa spec v1.15.0 and fixes three real defects found by a same-day
deep audit that ran `jfusa`'s own commands against this repo and compared
output to the spec (SoundMatt/java-FuSa#33, #34, #35, #36). `SPEC_VERSION`
1.14.0 → 1.15.0.

### Fixed

- **`fmea`: `coveragePct` could exceed 100%** (SoundMatt/java-FuSa#33).
  `Fmea.derive` maintained its own second, unanchored, unmasked
  method-detection regex instead of reusing `trace --func-coverage`'s
  denominator scanner, so it both matched method-declaration-shaped text
  *inside a text-block string literal* in `src/test` fixtures and never
  excluded the test-source tree at all — on this repo's own codebase,
  `coveragePct` came out to 111.9%. `Fmea.derive` now calls the same shared
  scanner `trace --func-coverage` uses (`Trace.scanComponentMethods`, new),
  which excludes `src/test`/`tests` (`LintRules.isTestSourcePath`, new) —
  making `componentsAnalyzed` a provable subset of `componentsInProject` by
  construction — plus a defensive `Fmea.clampCoveragePct` backstop per the
  spec's explicit MUST that the value never exceed 100 regardless.
- **`tara`: `impact` axes used the wrong closed-enum vocabulary, and
  `deriveRisk` didn't implement the spec's risk-combination table**
  (SoundMatt/java-FuSa#34). The fixed threat catalogue emitted
  `high`/`medium`/`low` for `impact.{safety,financial,operational,privacy}`
  — the vocabulary reserved for `attackFeasibility` — instead of the
  spec-mandated `critical`/`major`/`moderate`/`negligible`. Independently,
  `Tara.deriveRisk`'s hand-rolled `if`-chain diverged from the spec's 4×4
  risk-combination table on 7 of 16 cells once fed the correct vocabulary
  (e.g. a `major`-impact/`high`-feasibility threat — spec: `high` risk — was
  silently rated `low`). Both fixed: the catalogue now uses the correct
  vocabulary, and `deriveRisk` looks up the verbatim spec table.
- **`comp`: `extractMethodName` still produced `name: "unknown"` for ~51% of
  entries** (SoundMatt/java-FuSa#35). The old regex only matched a
  declaration with exactly one token between the access modifier and the
  method name, so any additional modifier (`static`), a generic/parameterized
  return type (`List<Entry>`), or a no-arg constructor fell through to
  `"unknown"`. Rewritten to take the last identifier immediately before an
  opening paren in the text before the line's first `{` — a signature shape
  invariant regardless of how many modifier/generic/return-type tokens
  precede it. On this repo's own `comp-report.json`: 276/542 (51%) → 0/545.

### Changed

- **§1.6 rule 4 (implementer guidance):** `trace --func-coverage`'s
  denominator, `fmea`'s derivation, and `comp`'s complexity scan no longer
  maintain independent method-detection/exclusion logic — `trace` and `fmea`
  now share one scanner (`Trace.scanComponentMethods`) and one test-tree
  exclusion helper (`LintRules.isTestSourcePath`), per the spec's guidance to
  reuse rather than re-implement.
- Verified (no code change needed): `fmea`/`tara`/`safety-case`/`sas`
  already implement §1.6.2's new attestation carry-forward MUST correctly
  (each `build` loads any prior saved artifact's `attestation` before
  rebuilding) — added the one missing regression test, for `safety-case`.

## v0.5.0 — 2026-07-28

Adopts x-FuSa spec v1.14.0 across `hara`/`fmea`/`tara`/`safety-case`/`sas`/`sci`
(SoundMatt/java-FuSa#31): real field-level schemas (§9.2/§9.3), a
content-quality baseline (§1.6), and coverage metrics (§9.2). `SPEC_VERSION`
1.10.12 → 1.14.0.

### Added

- **`.fusa-hara.json` §1.2.5 schema.** `hara` is now a *validator* over an
  author-maintained input file, not a hardcoded 3-hazard generator:
  `operationalSituations[]`/`hazards[]`/`safetyGoals[]`, each hazard's
  `risk.asil` derived from `severity`×`exposure`×`controllability` (ISO
  26262-3:2018 Table 4 — the lookup table was previously wrong in several
  cells; ported the correct table), `safetyGoals[].fssrRefs` enforced as
  **MUST, ≥1 entry** resolving into `.fusa-reqs.json`, a `completeness` block
  (dangling-reference/ASIL/fssrRefs coverage), `--init` scaffolds **empty**
  arrays (never dummy rows, per §1.6 rule 1), `--format json|text`.
- **`fmea.json` §9.2 schema.** `entries[]` (`item`/`file`/`failureMode`/
  `effect`/`cause`/`severity`/`actionPriority`/`mitigations`/`requirementIds`),
  `ratingScale`, `summary.coveragePct` against the same public-method
  denominator as `trace --func-coverage` (`componentsInventoryMethod`
  documents the methodology), `--min-coverage N`. `failureMode`/`effect`/
  `cause` are now derived from the method's actual return type/parameter
  count/name instead of one fixed sentence repeated for every entry — the
  exact "blanket qualitative fallback" the spec's content-quality audit
  flags (§1.6.1 rule B).
- **`tara.json` §9.2 schema.** `threats[]` with an **SFOP impact object**
  (`safety`/`financial`/`operational`/`privacy`, ISO 21434 Clause 15.7)
  replacing the single generic `impactRating` string; `risk` derived from
  `attackFeasibility` × the highest SFOP axis; `treatment`
  (mitigate/accept/transfer/avoid); `summary.coveragePct` +
  `assetInventoryMethod` — honestly disclosed as a fixed cross-project
  catalogue, not a per-project asset-discovery scan; `--min-coverage N`.
- **`safety-case.json` §9.2 GSN schema.** Replaced the ad hoc `goals[]`/
  `evidence[]` arrays with real GSN Community Standard v3 `nodes[]`
  (`goal`/`strategy`/`solution`/`context`/`assumption`/`justification`) and
  `edges[]` (`supportedBy`/`inContextOf`), plus a `completeness` block
  (`totalGoals`/`goalsWithEvidence`/`undeveloped`). Goal text now names the
  actual project and standard instead of the generic "the system is
  acceptably safe for its intended use" boilerplate the spec calls out as
  non-conformant.
- **`sas.json` §9.3 schema.** `sas` now also writes `sas.json`
  (`checklist[]`/`summary`/`attestation`) alongside the existing `sas.md`.
- **`sci.json` hash-field fix (§2.7).** `artifacts[].hash` (renamed from
  `sha256`/`path` to the canonical `hash`/`file`) is `sha256:`-prefixed, per
  the rule that a field *named* `hash` carries `"algo:value"` while a field
  named for its algorithm carries bare hex — the old code had this
  backwards (field named `sha256` holding an already-prefixed value). A
  missing file is now omitted from `artifacts[]` entirely instead of
  emitting a placeholder empty-string hash. Added `version`.
- **Content-quality baseline (§1.6/§1.6.1) — `FUSA-STUB001`/`FUSA-STUB002`.**
  New `qualitybar` package, wired into `hara`/`fmea`/`tara`/`safety-case`/
  `sas`: `FUSA-STUB001` (deny-list placeholder-text scan, always `ERROR`,
  suppressible only via `jfusa disposition add FUSA-STUB001 <file> accepted
  "<reason>"`) and `FUSA-STUB002` (distinct-value-ratio < 0.1 across ≥10
  entries, `WARNING` by default, not gating unless `--strict`/
  `--require-attestation`).
- **Attestation (§1.6.2) — new `attestation` package.** A document-level
  `attestation` object (`status`/`implementationAuthor`/`independentReviewer`/
  `reviewedAt`/`contentHash`) suppresses `FUSA-STUB002` once it is a
  non-stale (`contentHash` recomputed via a new RFC 8785 canonicalizer,
  `internal.CanonJson`), genuinely independent (`independentReviewer` ≠
  `implementationAuthor`) review. A previously-added attestation is carried
  forward verbatim on every regeneration.
- `internal.CanonJson` — RFC 8785 (JSON Canonicalization Scheme)
  canonicalizer + `sha256:`-prefixed hashing, mirroring FuSaOps' own
  canonicalizer so both projects compute the same hash over the same
  content.
- `Json.Writer.rawValue(Object)` — recursively serialises an arbitrary
  decoded-JSON object graph, so an artifact's entries can be built once as
  plain `Map`/`List` and reused for both JSON output and canonical hashing.

### Fixed

- **`Json.prettify` indentation drift after an empty `{}`/`[]`.** The
  pretty-printer decremented its indent level after *every* closing
  bracket, including one whose matching open bracket never incremented it
  (the `{}`/`[]` collapse-onto-one-line case) — every sibling following an
  empty collection was rendered one indent level shallow. Silent before
  (JSON stays valid regardless of whitespace) but visible now that `hara
  --init`'s empty-array scaffold is a first-class, spec-required shape
  rather than an edge case.

### Tests

- Added `CanonJsonTest`, `AttestationTest`, `QualityBarTest`, `FmeaTest`,
  `TaraTest`, `SafetyCaseTest`, `SasTest`, `SciTest`; rewrote `HaraTest` for
  the new §1.2.5 schema; updated `GapCoverageTest` for the renamed
  `Fmea.FailureMode` record. Registered 32 new requirement ids in
  `.fusa-reqs.json`.

## v0.4.8 — 2026-07-28

### Fixed
- **`trace --format json` could emit invalid JSON** (issue #28):
  `Trace.loadReqsMeta()` read `.fusa-reqs.json` with a hand-rolled,
  brace-counted scanner instead of the project's own `Json` parser, so a
  `title` containing an escaped quote (`\"`) desynced that object's
  boundary and corrupted every subsequent entry in the array. Replaced it
  with `Json.parseObject()`/`Json.arr()`/`Json.str()`, which already
  handle escaped quotes and nesting correctly. Added a regression test
  exercising a title with an escaped quote followed by another
  requirement, asserting the rendered JSON is valid and neither entry is
  corrupted.

## v0.4.7 — 2026-07-27

### Added
- `docker-publish.yml` now notifies `SoundMatt/FuSaOps` via `repository_dispatch`
  (`xfusa-released`) after a successful image push, so FuSaOps rebuilds its
  bundled image promptly instead of waiting for its weekly cron. Requires a
  `FUSAOPS_DISPATCH_TOKEN` secret in this repo; falls back silently
  (`continue-on-error`) to the weekly rebuild if it's not set.

### Fixed

- **`qualify` ignored `--output`/`--format`** (#24): always wrote
  `qualify-report.json` to the project root and always printed the
  plain-text summary, regardless of flags. `cmdQualify` now threads
  `--output`/`--format` through to `Qualify.run()`/`generateReport()`;
  `--format json` prints the report body to stdout instead of the summary
  line, and the sibling `.sha256` hash file is named after the actual
  output filename.
- **`release` ignored `--output-dir`** (#25): always wrote `sbom.json`,
  `provenance.json`, and `artifact-manifest.json` to the project root.
  `cmdRelease` now parses `--output-dir` (defaulting to the project root)
  and `Release.run()` creates it if missing before writing there.
- **`audit-pack` ignored `--output`** (#26): always wrote `audit-pack.zip`
  to the project root. `cmdAuditPack` now threads `--output` through to
  `AuditPack.generate()`.
- **`audit-pack`'s ZIP had no `manifest.json`** (#27): it bundled release's
  `artifact-manifest.json` under the wrong entry name as a stand-in for its
  own manifest, instead of the spec-required top-level `manifest.json`
  (`kind: "audit-manifest"`, `files[]` with `path`/`size`/`sha256`).
  `AuditPack` now generates its own manifest with the correct shape;
  `artifact-manifest.json` is still bundled as an ordinary evidence file
  when present, just no longer misnamed as the pack's manifest.

### Tests / Requirements

- **Closed all 37 orphan requirement-tag gaps** found by running
  `jfusa trace` against this repo: `REQ-CYBER001`-`REQ-CYBER020`,
  `REQ-ANA001`-`REQ-ANA006`, `REQ-RT001`-`REQ-RT003`, `REQ-CFG001`/`002`/
  `003`/`005`, `REQ-ERR001`-`REQ-ERR003`, and `REQ-NF001` were tagged
  in real production source with an existing `//fusa:test` on each, but
  were never registered in `.fusa-reqs.json`. Registered all 37 with
  titles derived from each rule's own description/doc comment. Orphan-tag
  count: 37 → 0; untested-requirement count: unchanged at 0.

## v0.4.6 — 2026-07-27

### Fixed

- **Orphan release cleanup** (#21): a no-prefix `0.4.3` release existed while
  tag `v0.4.3` (same commit, `7652feb`) had no corresponding GitHub release.
  Created a proper `v0.4.3` release reusing the original body, deleted the
  stray `0.4.3` release, and removed the redundant bare `0.4.3` tag (`v0.4.3`
  remains as the canonical tag).
- **`SPEC_VERSION` build-arg never actually reached published images** (#21):
  `.github/workflows/docker-publish.yml`'s `build-args` only passed `VERSION`,
  `GIT_COMMIT`, and `BUILD_DATE` — `SPEC_VERSION` was silently defaulted by
  the `Dockerfile`, so every published image's OCI labels were stamped with a
  stale spec version regardless of the actual release. Added
  `SPEC_VERSION=1.10.12` to the workflow's build-args, and bumped the
  `Dockerfile`'s own stale `ARG` defaults (`VERSION=0.3.0` → `0.4.6`,
  `SPEC_VERSION=1.10.4` → `1.10.12`) so a local `docker build .` per the
  README's Quick Start also gets correct values.
- **README had 3 stale "v1.9" spec references** (#21) while `FuSa.SPEC_VERSION`
  has been `1.10.12` since v0.4.2 and `Config.java` already targets "x-FuSa
  spec v1.10 §1.2.1": the spec badge, the intro prose, and the example
  `.fusa.json`'s `"schema"` field all now read v1.10.

## v0.4.5 — 2026-07-27

### Tests / Requirements

- **Boosted function-tag coverage from 27% to 96%** (66/244 → 236/245 public
  functions now carry a `//fusa:req` tag directly above them, measured via
  `jfusa trace --dir . --func-coverage 100`). Tagged essentially every
  previously-untagged public method across the codebase, registering ~70 new
  requirement IDs in `.fusa-reqs.json` (following the existing
  `REQ-<AREA><NNN>` scheme) and adding a matching `//fusa:test` tag for each —
  reusing an existing test wherever one already genuinely exercised the
  method, and writing a new one (18 new test methods, incl. a new
  `SlsaTest.java`) where none existed.
  - Core value types (`FuSa.java`, `internal/Json.java`, `config/Config.java`):
    `REQ-NF002..006`, `REQ-JSON001..006`, `REQ-CFG010..012`.
  - Engine/report plumbing: `REQ-ENG009..012`, `REQ-REPORT001..005`.
  - Feature commands (`qualify`, `vuln`, `pr`, `comp`, `slsa`, `release`,
    `runtime`, gap-report family for `iso26262`/`iec61508`/`iso21434`/`do178`/
    `unece`, `lint` shared scanner utilities, `coverage`): one or a small
    cluster of new IDs per class, grouping tightly-related methods under a
    shared ID rather than minting one per method.
  - Remaining low-traffic commands (`badge`, `boundary`, `coupling`, `hooks`,
    `disposition`, `fmea`, `template`, `verify`, `auditpack`, `diff`, `hara`,
    `iec62443`, `impact`, `metrics`, `misra`, `safetycase`, `sas`, `sci`,
    `tara`, `trace` `Annotation`): one new ID per file.
  - New genuine tests were added for previously wholly-untested behavior,
    e.g. `Registry.get()`, `Engine.Result.empty()`, `Json.obj()/arr()`,
    `Qualify.generateReport()` 2-arg overload, `Release.generateManifest()`,
    `Vuln`/`SLSA001-3`/`IEC62443-001`/`MISRA001` rule fire/silent behavior,
    `Impact.analyze()/generate()`.
  - Left deliberately untagged (not gameable without fabricating tests):
    `cmd.Main.main()` (calls `System.exit()`, unsafe to unit-test directly)
    and 8 anonymous `Rule` test fixtures in `EngineTest`/`ReportTest`/
    `ConformanceTest` used to exercise engine isolation/failure-handling —
    these are test-only scaffolding, not production requirements.
  - Zero regressions: all pre-existing tests still pass; 18 new tests added
    (339 → 357 total), `//fusa:test` coverage of registered requirements
    remains 100%.

## v0.4.4 — 2026-07-27

### Tests

- **Closed all 40 untested requirement gaps** (test coverage 49% → 100%, 79/79
  requirements now have a matching `//fusa:test` tag). Root causes were a mix
  of genuinely-missing tests and existing-but-untagged tests:
  - `REQ-CYBER001/005/007/020`: existing passing tests tagged.
  - `REQ-CYBER002/003/004/006/008/009/010/012/013/014/015/016/018/019`: 14 new
    tests added in `CyberRulesTest.java`, each exercising the specific CWE
    pattern the rule's regex/heuristic actually matches.
  - `REQ-CFG001/002/005`, `REQ-ERR001`: existing `ConfigTest` tests tagged
    (`load`/`parse`/`defaultConfig`/`NoConfigException` round-trips already
    covered these).
  - `REQ-CFG003` (`validateFormat`), `REQ-NF003` (`Standard.canonicalId`/`of`):
    new tests added — neither had any prior test.
  - `REQ-CFG007` (per-rule exclude-list filtering in `Engine.runFilter`): new
    test — the exclude-list mechanism itself was never directly tested.
  - `REQ-ERR003` (`CheckFailedException`): new constructor/message test.
  - `REQ-ANA001/003/004/005`: existing `AnalyzeRulesTest` tests tagged.
  - `REQ-ANA002` (unclosed resource), `REQ-ANA006` (exception swallowed
    without cause chaining): new tests — neither rule had a test at all.
  - `REQ-RT001/002/003`: existing `RuntimeTest` watchdog/heartbeat/
    safe-state-guard tests tagged.
  - `REQ-FUSA001`: existing `EngineTest` empty-dir/with-config tests tagged
    (already exercised `FUSA001`'s fire/silent behavior, just untagged).
  - `REQ-FUSA002/003/004/005` (pom.xml/LICENSE/README/CI-config presence
    checks): 8 new tests (fire + silent case for each) — none of these four
    built-in rules had any test coverage before.

## v0.4.3 — 2026-07-27

### Added

- **x-FuSa spec §1.4.1 / §5 `--func-coverage N`**: `Trace.computeFuncCoverage()` measures the
  percentage of public methods (excluding getters/setters, constructors, and no-op
  `id()`/`description()`/`activate()` interface shims) carrying a `//fusa:req` tag directly
  above them. `jfusa trace --func-coverage N` prints the figure and exits `1` when below `N`;
  `N=0` disables the gate, mirroring `--req-coverage`'s semantics.
- **x-FuSa spec §1.4.1 dangling `//fusa:test` reference detection**: new rule `TRACE002`
  (`Trace.RuleDanglingTestRef`) flags any `//fusa:test <ID>` tag whose `<ID>` is not registered
  in `.fusa-reqs.json` as a `check` WARNING, per the spec's "malformed annotation" treatment.
  Skipped entirely when the project has no `.fusa-reqs.json` (nothing to validate against).

### Fixed

- **Annotation scanner false positives**: `Trace.scanAnnotations()` previously matched
  `//fusa:req`/`//fusa:test`-shaped text anywhere in a `.java` file's raw text, including inside
  string literals, multi-line text blocks, and prose within unrelated `//` comments — all of
  which this repo's own test fixtures (e.g. `TraceTest`, `Spec11ConformanceTest`) construct
  routinely when writing example source under test. A self-scan of java-FuSa previously
  surfaced dozens of garbage "requirement ids" (`REQ-001`, `REQ-KIND`, `must`, `or`, ...) from
  this. The scanner now tracks string/text-block state per line and only accepts a tag when it
  is the line's own first genuine `//` comment, eliminating the false positives; `--func-coverage`
  and the new dangling-reference check reuse the same filtering.

### Requirement retrofit (issue #18)

- Tagged previously-orphan core safety methods: `Engine.run()` (`REQ-ENG008`), `Sign.generateKey()`
  /`sign()`/`verify()` (`REQ-SIGN001`–`003`), `Hara.deriveAsil()` (`REQ-HARA001`), and
  `Trace.buildMatrix()` (`REQ-TRACE004`) — plus matching `//fusa:test` tags and new `HaraTest`.
- Registered and test-tagged the previously-implemented-but-unregistered `REQ-LINT001`–`010`,
  `REQ-ENG004`/`005`, and `REQ-RELEASE001`/`002` requirements; added six new `LintRulesTest`
  cases (LINT003/004/006/008/009/010) and an `Engine` rule-isolation test (`REQ-ENG002`) that
  had no coverage at all before this pass.
- Added `//fusa:test` tags to a safety-relevant subset of `MainTest`'s CLI smoke tests
  (`check`, `trace`, `qualify`, `release`), modeled on `GapCoverageTest`/`TraceTest`'s style.
- Partial progress on issue #18's ~60-requirement list — `REQ-CYBER*`, `REQ-ANA*`, `REQ-CFG*`,
  and `REQ-RT*` remain untested/unregistered and are left for a future pass.

## v0.4.2 — 2026-07-27

### Fixed

- **SPEC_VERSION**: Updated `FuSa.SPEC_VERSION` from `"1.10.4"` to `"1.10.12"` to match the
  current x-FuSa spec; also updated `pom.xml` description accordingly.

- **P1 test-coverage (0% inner classes)**: Added `GapCoverageTest.java` with 47 tests
  targeting previously uncovered types: `FuSa.InvalidConfigException`, `Coupling.CouplingEntry`,
  `Coverage.CoverageReport`, `Fmea.FmeaEntry`, `Json.JsonParseException`, `Verify.Evidence`.

- **P2 test-coverage (low-coverage classes)**: Expanded coverage for `Coverage.RuleCoverageGate`
  (gate-fires/no-fires scenarios), `Template` (all four template kinds), `CyberRules.RuleCWE352CSRF`
  (Servlet/Controller with and without CSRF token), `CyberRules.RuleCWE611XXE` (XXE present/absent/
  fusa:unsafe annotation), `Boundary` (dependency graph, Mermaid/DOT output, stdlib exclusion),
  and `Hooks` (install/remove lifecycle).

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
