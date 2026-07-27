package com.soundmatt.jfusa.slsa;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * SLSA supply-chain compliance gap-report command.
 *
 * <p>Per spec v1.10 §9.3: {@code slsa} is a gap-report command with
 * {@code standard: "slsa"}, {@code kind: "gap-report"}, {@code --level L1|L2|L3|L4}.
 * Output: {@code slsa-gap-report.json}.
 */
public final class Slsa {

    public static final String SLSA_GAP_REPORT = "slsa-gap-report.json";

    static {
        Engine.DEFAULT.mustRegister(new RuleProvenancePresent());
        Engine.DEFAULT.mustRegister(new RuleCodeownersPresent());
        Engine.DEFAULT.mustRegister(new RuleSBOMPresent());
    }

    private Slsa() {}
    public static void activate() {}

    // ── Gap-report command (§9.3 canonical) ─────────────────────────────────

    //fusa:req REQ-SLSA001
    public record SlsaObjective(String id, String title, String clause,
                                 String status, List<String> evidence, List<String> findings) {}

    //fusa:req REQ-SLSA001
    public static List<SlsaObjective> buildObjectives(Path root, String level) {
        List<SlsaObjective> objs = new ArrayList<>();
        int levelNum = levelNum(level);

        // L1: Source provenance / build scripted
        objs.add(obj("SLSA-L1-1", "Source version controlled",    "L1",
                Files.exists(root.resolve(".git")) ? "satisfied" : "gap",
                List.of(".git"), List.of()));
        objs.add(obj("SLSA-L1-2", "Build scripted",               "L1",
                hasAny(root, "Makefile", "pom.xml", "build.gradle") ? "satisfied" : "gap",
                List.of("Makefile"), List.of()));

        // L2: Provenance + SBOM
        String provStatus = Files.exists(root.resolve("provenance.json")) ? "satisfied" : "gap";
        objs.add(obj("SLSA-L2-1", "Build provenance present",     "L2",
                levelNum >= 2 ? provStatus : "satisfied",
                List.of("provenance.json"), provStatus.equals("gap") ? List.of("SLSA001") : List.of()));
        String sbomStatus = Files.exists(root.resolve("sbom.json")) ? "satisfied" : "gap";
        objs.add(obj("SLSA-L2-2", "SBOM present (dependency disclosure)", "L2",
                levelNum >= 2 ? sbomStatus : "satisfied",
                List.of("sbom.json"), sbomStatus.equals("gap") ? List.of("SLSA003") : List.of()));
        objs.add(obj("SLSA-L2-3", "Artifact integrity (manifest with SHA-256)", "L2",
                Files.exists(root.resolve("artifact-manifest.json")) ? "satisfied" : "partial",
                List.of("artifact-manifest.json"), List.of()));

        // L3: CODEOWNERS / review gating
        boolean hasCodeowners = hasAny(root, "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS");
        objs.add(obj("SLSA-L3-1", "Code ownership defined (CODEOWNERS)", "L3",
                levelNum >= 3 ? (hasCodeowners ? "satisfied" : "gap") : "satisfied",
                List.of("CODEOWNERS"), !hasCodeowners && levelNum >= 3 ? List.of("SLSA002") : List.of()));

        // L4: Hermetic / reproducible build (informational)
        objs.add(obj("SLSA-L4-1", "Hermetic / reproducible build", "L4",
                levelNum >= 4 ? "gap" : "satisfied",
                List.of(), levelNum >= 4 ? List.of() : List.of()));
        return objs;
    }

    private static SlsaObjective obj(String id, String title, String clause,
                                      String status, List<String> evidence, List<String> findings) {
        return new SlsaObjective(id, title, clause, status, evidence, findings);
    }

    private static boolean hasAny(Path root, String... paths) {
        for (String p : paths) if (Files.exists(root.resolve(p))) return true;
        return false;
    }

    private static int levelNum(String level) {
        return switch (level.toUpperCase()) {
            case "L1" -> 1; case "L2" -> 2; case "L3" -> 3; case "L4" -> 4; default -> 2;
        };
    }

    //fusa:req REQ-SLSA002
    public static void generateGapReport(Path root, String level, String format) throws IOException {
        List<SlsaObjective> objs = buildObjectives(root, level);
        long satisfied = objs.stream().filter(o -> "satisfied".equals(o.status())).count();
        long partial   = objs.stream().filter(o -> "partial".equals(o.status())).count();
        long gaps      = objs.stream().filter(o -> "gap".equals(o.status())).count();

        if ("json".equals(format)) {
            var w = new Json.Writer();
            w.objectStart();
            w.field("schemaVersion", FuSa.SPEC_VERSION);
            w.field("kind", "gap-report");
            w.field("tool", "java-FuSa");
            w.field("toolVersion", FuSa.VERSION);
            w.field("language", "java");
            w.field("generatedAt", Instant.now().toString());
            w.field("standard", "slsa");
            w.field("level", level);
            w.key("objectives"); w.arrayStart();
            for (SlsaObjective o : objs) {
                w.objectStart();
                w.field("id", o.id()); w.field("title", o.title()); w.field("clause", o.clause());
                w.field("status", o.status());
                w.key("evidence"); w.arrayStart(); for (String e : o.evidence()) w.value(e); w.arrayEnd();
                w.key("findings"); w.arrayStart(); for (String f : o.findings()) w.value(f); w.arrayEnd();
                w.objectEnd();
            }
            w.arrayEnd();
            w.key("summary"); w.objectStart();
            w.field("total", objs.size()); w.field("satisfied", satisfied);
            w.field("partial", partial); w.field("gaps", gaps);
            w.objectEnd();
            w.objectEnd();
            Files.writeString(root.resolve(SLSA_GAP_REPORT), w.toPretty() + "\n");
            System.out.println("SLSA gap report written: " + SLSA_GAP_REPORT);
        } else {
            System.out.println("SLSA " + level + " Gap Report");
            System.out.println("=".repeat(50));
            for (SlsaObjective o : objs) {
                System.out.printf("%-12s %-10s %s%n", o.clause(), o.status(), o.title());
            }
            System.out.printf("%nSummary: %d satisfied, %d partial, %d gap(s) of %d total%n",
                    satisfied, partial, gaps, objs.size());
        }
    }

    // ── Engine rules (FUSA-registered, also used in check) ───────────────────

    static final class RuleProvenancePresent implements Rule {
        public String id() { return "SLSA001"; }
        public String description() { return "Build provenance must be present (SLSA L2)."; }

        //fusa:req REQ-SLSA003
        public List<Finding> run(Path root, Config cfg) {
            if (!Files.exists(root.resolve(com.soundmatt.jfusa.release.Release.PROVENANCE_FILE))) {
                return List.of(Finding.builder("SLSA001", Severity.WARNING,
                        "no provenance.json — SLSA L2 requires signed build provenance",
                        new FuSa.Location("provenance.json"))
                        .category(FuSa.Category.SUPPLY_CHAIN).standard("slsa").clause("L2")
                        .remediation("run 'jfusa release' to generate provenance.json")
                        .build());
            }
            return List.of();
        }
    }

    static final class RuleCodeownersPresent implements Rule {
        public String id() { return "SLSA002"; }
        public String description() { return "CODEOWNERS file should be present (SLSA L3 review requirement)."; }

        //fusa:req REQ-SLSA004
        public List<Finding> run(Path root, Config cfg) {
            for (String p : List.of("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")) {
                if (Files.exists(root.resolve(p))) return List.of();
            }
            return List.of(Finding.builder("SLSA002", Severity.INFO,
                    "no CODEOWNERS file — SLSA L3 recommends code ownership for review gating",
                    new FuSa.Location("CODEOWNERS"))
                    .category(FuSa.Category.SUPPLY_CHAIN).standard("slsa").clause("L3")
                    .remediation("add a CODEOWNERS file defining code ownership")
                    .build());
        }
    }

    static final class RuleSBOMPresent implements Rule {
        public String id() { return "SLSA003"; }
        public String description() { return "SBOM must be present (SLSA L2 + ISO 21434 supply chain)."; }

        //fusa:req REQ-SLSA005
        public List<Finding> run(Path root, Config cfg) {
            if (!Files.exists(root.resolve(com.soundmatt.jfusa.release.Release.SBOM_FILE))) {
                return List.of(Finding.builder("SLSA003", Severity.WARNING,
                        "no sbom.json — SLSA L2 and ISO 21434 require a software bill of materials",
                        new FuSa.Location("sbom.json"))
                        .category(FuSa.Category.SUPPLY_CHAIN).standard("slsa").clause("L2")
                        .remediation("run 'jfusa release' to generate sbom.json")
                        .build());
            }
            return List.of();
        }
    }
}
