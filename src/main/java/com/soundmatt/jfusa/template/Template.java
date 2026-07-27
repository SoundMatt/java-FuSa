package com.soundmatt.jfusa.template;

import com.soundmatt.jfusa.FuSa;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDate;

/**
 * Safety plan, test evidence, and HARA document template generators.
 */
public final class Template {

    private Template() {}

    //fusa:req REQ-TEMPLATE001
    public static void generate(Path root, String kind, String name) throws IOException {
        switch (kind) {
            case "safety-plan"     -> safetyPlan(root, name);
            case "test-evidence"   -> testEvidence(root, name);
            case "hara"            -> haraTemplate(root, name);
            case "qualification-plan" -> qualificationPlan(root, name);
            default -> { System.err.println("Unknown template: " + kind); System.exit(FuSa.EXIT_USAGE); }
        }
    }

    static void safetyPlan(Path root, String name) throws IOException {
        String safe = name.replaceAll("[^a-zA-Z0-9_-]", "_");
        Path out = root.resolve("docs/" + safe + "-safety-plan.md");
        Files.createDirectories(out.getParent());
        String content = """
                # Safety Plan: %s

                **Document ID:** SP-%s-001
                **Issue:** 1.0
                **Date:** %s
                **Standard:** ISO 26262 / IEC 61508
                **Classification:** Confidential

                ## 1. Scope

                This document defines the safety plan for **%s**.

                ## 2. Safety Lifecycle

                | Phase | Activity | Owner | Status |
                |---|---|---|---|
                | Concept | Hazard Analysis (HARA) | TBD | Open |
                | System Design | Safety Requirements | TBD | Open |
                | SW Design | Software Safety Analysis | TBD | Open |
                | Implementation | Coding Standards Review | TBD | Open |
                | Integration | Module/Integration Testing | TBD | Open |
                | Validation | System Validation | TBD | Open |
                | Release | Safety Assessment | TBD | Open |

                ## 3. Safety Requirements

                Safety requirements are tracked in `.fusa-reqs.json`. Run `jfusa trace` for traceability.

                ## 4. Verification Approach

                - Static analysis: `jfusa check`
                - Security analysis: `jfusa cyber`
                - Qualification: `jfusa qualify`
                - Evidence: `jfusa verify`

                ## 5. Assumptions of Use

                _Document assumptions of use and known limitations here._

                ## 6. References

                - ISO 26262:2018 Road Vehicles — Functional Safety
                - IEC 61508:2010 Functional Safety of E/E/PE Safety-related Systems
                - x-FuSa Spec v%s
                """.formatted(name, safe.toUpperCase(), LocalDate.now(), name, FuSa.SPEC_VERSION);
        Files.writeString(out, content);
        System.out.println("Safety plan template: " + out);
    }

    static void testEvidence(Path root, String name) throws IOException {
        String safe = name.replaceAll("[^a-zA-Z0-9_-]", "_");
        Path out = root.resolve("docs/" + safe + "-test-evidence.md");
        Files.createDirectories(out.getParent());
        String content = """
                # Test Evidence Report: %s

                **Document ID:** TE-%s-001
                **Issue:** 1.0
                **Date:** %s
                **Standard:** DO-178C §11.14

                ## 1. Test Summary

                | Test Suite | Pass | Fail | Skip | Coverage |
                |---|---|---|---|---|
                | Unit Tests | TBD | TBD | TBD | TBD |
                | Integration Tests | TBD | TBD | TBD | TBD |
                | Qualification Suite | TBD | TBD | TBD | TBD |

                ## 2. Qualification Results

                Run `jfusa qualify` to generate `qualify-report.json`.

                ## 3. Coverage Evidence

                Run `jfusa coverage` to analyse JaCoCo output.

                ## 4. Test Cases

                | TC-ID | Description | Result | Evidence File |
                |---|---|---|---|
                | TC-001 | FuSa core types | PASS | qualify-report.json |
                | TC-002 | Config load/save | PASS | qualify-report.json |
                | TC-003 | Engine rules | PASS | qualify-report.json |
                | TC-004 | Report rendering | PASS | qualify-report.json |
                | TC-005 | LINT rules | PASS | qualify-report.json |

                ## 5. Anomaly Records

                See `.fusa-problems.json` managed via `jfusa pr`.
                """.formatted(name, safe.toUpperCase(), LocalDate.now());
        Files.writeString(out, content);
        System.out.println("Test evidence template: " + out);
    }

    static void haraTemplate(Path root, String name) throws IOException {
        String safe = name.replaceAll("[^a-zA-Z0-9_-]", "_");
        Path out = root.resolve("docs/" + safe + "-hara.md");
        Files.createDirectories(out.getParent());
        String content = """
                # Hazard Analysis and Risk Assessment: %s

                **Document ID:** HARA-%s-001
                **Issue:** 1.0
                **Date:** %s
                **Standard:** ISO 26262-3

                ## 1. Hazardous Events

                | HE-ID | Hazard | Severity | Exposure | Controllability | ASIL | Description |
                |---|---|---|---|---|---|---|
                | HE-001 | _Describe hazard_ | S2 | E3 | C2 | ASIL-B | _Describe_ |
                | HE-002 | _Describe hazard_ | S3 | E4 | C3 | ASIL-D | _Describe_ |

                ## 2. ASIL Derivation

                ASIL = f(Severity, Exposure, Controllability) per ISO 26262-3 Table 2.

                ## 3. Safety Goals

                | SG-ID | Description | ASIL | Linked HARA |
                |---|---|---|---|
                | SG-001 | _Safety goal_ | ASIL-B | HE-001 |

                ## 4. Functional Safety Requirements

                Derived safety requirements are captured in `.fusa-reqs.json`.
                Run `jfusa hara` to generate `.fusa-hara.json`.
                """.formatted(name, safe.toUpperCase(), LocalDate.now());
        Files.writeString(out, content);
        System.out.println("HARA template: " + out);
    }

    static void qualificationPlan(Path root, String name) throws IOException {
        String safe = name.replaceAll("[^a-zA-Z0-9_-]", "_");
        Path out = root.resolve("docs/" + safe + "-qualification-plan.md");
        Files.createDirectories(out.getParent());
        String content = """
                # Tool Qualification Plan: %s

                **Document ID:** TQP-%s-001
                **Issue:** 1.0
                **Date:** %s
                **Standard:** DO-178C §12.2 / ISO 26262-8:11

                ## 1. Tool Description

                jfusa v%s — x-FuSa spec-compliant functional safety tool suite for Java projects.

                ## 2. Tool Classification

                TQL-5 (criteria 1: no output directly to airborne software)

                ## 3. Qualification Method

                - Tool Operational Requirements (TOR)
                - Test Cases (TC-001 through TC-010 in qualify-report.json)
                - Tool Qualification Data (qualification archive)

                ## 4. Test Strategy

                Run `jfusa qualify` to execute the built-in qualification suite and generate
                `qualify-report.json` with SHA-256 integrity hash.

                ## 5. Tool Vendor Information

                - Vendor: SoundMatt
                - Version: %s
                - Specification: x-FuSa v%s
                - License: MPL-2.0
                """.formatted(name, safe.toUpperCase(), LocalDate.now(),
                        FuSa.VERSION, FuSa.VERSION, FuSa.SPEC_VERSION);
        Files.writeString(out, content);
        System.out.println("Qualification plan template: " + out);
    }
}
