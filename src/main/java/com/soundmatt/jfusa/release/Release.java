package com.soundmatt.jfusa.release;

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
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

/**
 * SBOM, build provenance, and artifact manifest — x-FuSa spec §7.
 */
public final class Release {

    public static final String SBOM_FILE       = "sbom.json";
    public static final String PROVENANCE_FILE = "provenance.json";
    public static final String MANIFEST_FILE   = "artifact-manifest.json";

    static {
        Engine.DEFAULT.mustRegister(new RuleSBOMPresent());
        Engine.DEFAULT.mustRegister(new RuleProvenancePresent());
    }

    private Release() {}
    public static void activate() {}

    // ── SBOM (x-FuSa SBOM v1) ────────────────────────────────────────────────

    public static void generateSBOM(Path projectRoot, Config cfg) throws IOException {
        String name = cfg != null ? cfg.project().name() : "unknown";
        String module = "com.soundmatt:" + name.toLowerCase() + ":" + FuSa.VERSION;
        var w = new Json.Writer();
        w.objectStart();
        // §3.1 common header
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "sbom");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        // §7 SBOM body
        w.field("format", "x-FuSa SBOM v1");
        w.field("module", module);
        w.key("components"); w.arrayStart();
        // Maven runtime dependencies would be populated here; empty for no external deps
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(projectRoot.resolve(SBOM_FILE), w.toPretty() + "\n");
    }

    // ── Build provenance ──────────────────────────────────────────────────────

    public static void generateProvenance(Path projectRoot, Config cfg) throws IOException {
        String name = cfg != null ? cfg.project().name() : "unknown";
        String module = "com.soundmatt:" + name.toLowerCase() + ":" + FuSa.VERSION;
        var w = new Json.Writer();
        w.objectStart();
        // §3.1 common header
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "provenance");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        // §7 provenance body
        w.field("format", "x-FuSa provenance v1");
        w.field("module", module);
        w.field("builder", "maven");
        w.objectEnd();
        Files.writeString(projectRoot.resolve(PROVENANCE_FILE), w.toPretty() + "\n");
    }

    // ── Artifact manifest ─────────────────────────────────────────────────────

    public static void generateManifest(Path projectRoot, List<String> artifacts) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        // §3.1 common header
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "artifact-manifest");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        // §7 manifest body — artifacts with bare sha256 hex per spec
        w.field("format", "x-FuSa manifest v1");
        w.key("artifacts"); w.arrayStart();
        for (String art : artifacts) {
            Path p = projectRoot.resolve(art);
            if (Files.exists(p)) {
                String fullHash = sha256file(p);
                String bareHex = fullHash.startsWith("sha256:") ? fullHash.substring(7) : fullHash;
                w.objectStart();
                w.field("path", art);
                w.field("sha256", bareHex);
                w.objectEnd();
            }
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(projectRoot.resolve(MANIFEST_FILE), w.toPretty() + "\n");
    }

    public static void run(Path projectRoot, Config cfg) throws IOException {
        generateSBOM(projectRoot, cfg);
        generateProvenance(projectRoot, cfg);
        generateManifest(projectRoot, List.of(SBOM_FILE, PROVENANCE_FILE));
        System.out.println("Release artifacts generated: " + SBOM_FILE + ", " + PROVENANCE_FILE);
    }

    public static String sha256file(Path p) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = Files.readAllBytes(p);
            return "sha256:" + HexFormat.of().formatHex(md.digest(bytes));
        } catch (Exception e) {
            return "";
        }
    }

    // ── Rules ─────────────────────────────────────────────────────────────────

    static final class RuleSBOMPresent implements Rule {
        public String id() { return "RELEASE001"; }
        public String description() { return "SBOM (sbom.json) must be present for supply-chain compliance."; }

        //fusa:req REQ-RELEASE001
        public List<Finding> run(Path root, Config cfg) {
            if (!Files.exists(root.resolve(SBOM_FILE))) {
                return List.of(Finding.builder("RELEASE001", Severity.WARNING,
                        "no sbom.json found — run 'jfusa release' to generate",
                        new FuSa.Location(SBOM_FILE))
                        .category(FuSa.Category.SUPPLY_CHAIN)
                        .standard("SLSA").clause("L2")
                        .remediation("run 'jfusa release' to generate SBOM and provenance")
                        .build());
            }
            return List.of();
        }
    }

    static final class RuleProvenancePresent implements Rule {
        public String id() { return "RELEASE002"; }
        public String description() { return "Build provenance (provenance.json) must be present for SLSA compliance."; }

        //fusa:req REQ-RELEASE002
        public List<Finding> run(Path root, Config cfg) {
            if (!Files.exists(root.resolve(PROVENANCE_FILE))) {
                return List.of(Finding.builder("RELEASE002", Severity.WARNING,
                        "no provenance.json found — run 'jfusa release' to generate",
                        new FuSa.Location(PROVENANCE_FILE))
                        .category(FuSa.Category.SUPPLY_CHAIN)
                        .standard("SLSA").clause("L2")
                        .remediation("run 'jfusa release' to generate build provenance")
                        .build());
            }
            return List.of();
        }
    }
}
