package com.soundmatt.jfusa.slsa;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** SLSA L2/L3 supply-chain checks — provenance, CODEOWNERS, branch protection evidence. */
public final class Slsa {

    static {
        Engine.DEFAULT.mustRegister(new RuleProvenancePresent());
        Engine.DEFAULT.mustRegister(new RuleCodeownersPresent());
        Engine.DEFAULT.mustRegister(new RuleSBOMPresent());
    }

    private Slsa() {}
    public static void activate() {}

    static final class RuleProvenancePresent implements Rule {
        public String id() { return "SLSA001"; }
        public String description() { return "Build provenance must be present (SLSA L2)."; }

        public List<Finding> run(Path root, Config cfg) {
            if (!Files.exists(root.resolve(com.soundmatt.jfusa.release.Release.PROVENANCE_FILE))) {
                return List.of(Finding.builder("SLSA001", Severity.WARNING,
                        "no provenance.json — SLSA L2 requires signed build provenance",
                        new FuSa.Location("provenance.json"))
                        .category(FuSa.Category.SUPPLY_CHAIN).standard("SLSA").clause("L2").build());
            }
            return List.of();
        }
    }

    static final class RuleCodeownersPresent implements Rule {
        public String id() { return "SLSA002"; }
        public String description() { return "CODEOWNERS file should be present (SLSA L3 review requirement)."; }

        public List<Finding> run(Path root, Config cfg) {
            for (String p : List.of("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")) {
                if (Files.exists(root.resolve(p))) return List.of();
            }
            return List.of(Finding.builder("SLSA002", Severity.INFO,
                    "no CODEOWNERS file — SLSA L3 recommends code ownership for review gating",
                    new FuSa.Location("CODEOWNERS"))
                    .category(FuSa.Category.SUPPLY_CHAIN).standard("SLSA").clause("L3").build());
        }
    }

    static final class RuleSBOMPresent implements Rule {
        public String id() { return "SLSA003"; }
        public String description() { return "SBOM must be present (SLSA L2 + ISO 21434 supply chain)."; }

        public List<Finding> run(Path root, Config cfg) {
            if (!Files.exists(root.resolve(com.soundmatt.jfusa.release.Release.SBOM_FILE))) {
                return List.of(Finding.builder("SLSA003", Severity.WARNING,
                        "no sbom.json — SLSA L2 and ISO 21434 require a software bill of materials",
                        new FuSa.Location("sbom.json"))
                        .category(FuSa.Category.SUPPLY_CHAIN).standard("SLSA").clause("L2").build());
            }
            return List.of();
        }
    }
}
