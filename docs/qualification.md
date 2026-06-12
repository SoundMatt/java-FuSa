# Tool Qualification

## Overview

jfusa is qualified as a **Tool Qualification Level 5 (TQL-5)** tool per DO-178C §12.2,
as its output does not flow directly into airborne or safety-critical software artefacts.
For higher criticality use (TQL-4 or above), a full TQP is required.

## Qualification Method

The qualification method employed is **Tool Operational Requirements + Testing**:

1. **Tool Operational Requirements (TOR)**: Defined in `.fusa-reqs.json` and this document.
2. **Test Cases**: TC-001 through TC-010 in `qualify-report.json`, executed by `jfusa qualify`.
3. **Tool Qualification Data**: All evidence in `audit-pack.zip`.

## Running Qualification

```bash
java -jar target/jfusa.jar qualify
```

This produces `qualify-report.json` containing:
- Tool version and spec version
- Timestamp and runtime environment
- Results for TC-001 through TC-010
- Overall PASS/FAIL status
- SHA-256 integrity hash of the report itself

## Test Cases

| TC-ID | Name | Description |
|-------|------|-------------|
| TC-001 | FuSa core types | Severity.rank(), Category.jsonValue(), deriveCategory() |
| TC-002 | Fingerprint determinism | Same input → same fingerprint |
| TC-003 | Config round-trip | save + load preserves fields |
| TC-004 | Engine registration | DEFAULT contains FUSA001–005 |
| TC-005 | Engine run | Empty directory produces findings |
| TC-006 | Report text format | Contains finding messages |
| TC-007 | Report JSON format | Valid JSON with schema field |
| TC-008 | LINT001 detection | return null without annotation |
| TC-009 | CYBER001 detection | SQL string concatenation |
| TC-010 | Integrity hash | qualify-report.json SHA-256 is stable |

## Integrity Verification

The integrity hash in `qualify-report.json` covers all test case results.
To verify:

```bash
java -jar target/jfusa.jar sign verify qualify-report.json
```

## Tool Configuration Management

The tool itself is subject to `jfusa check`, ensuring its own source meets
all FUSA, LINT, ANA, and CYBER rules. See CI results for evidence.

## Deviation Process

Any deviations from TOR must be documented in `.fusa-problems.json`:

```bash
jfusa pr add DEV-001 "TC-007 partial result on JDK 17" minor
```
