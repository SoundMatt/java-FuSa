package com.soundmatt.jfusa;

import com.soundmatt.jfusa.analyze.AnalyzeRules;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.cyber.CyberRules;
import com.soundmatt.jfusa.do178.Do178;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.iec61508.Iec61508;
import com.soundmatt.jfusa.iec62443.Iec62443;
import com.soundmatt.jfusa.iso21434.Iso21434;
import com.soundmatt.jfusa.iso26262.Iso26262;
import com.soundmatt.jfusa.lint.LintRules;
import com.soundmatt.jfusa.release.Release;
import com.soundmatt.jfusa.report.Report;
import com.soundmatt.jfusa.slsa.Slsa;
import com.soundmatt.jfusa.unece.Unece;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * §11 conformance verification tests for java-FuSa v0.2.0.
 * Each test corresponds to a ▫️ verify or ⚠️ gap item in the spec §11 table.
 */
class Spec11ConformanceTest {

    @TempDir Path tmp;

    // ── Severity enum ──────────────────────────────────────────────────────────

    @Test
    void severity_jsonValues_areUppercase() {
        assertEquals("ERROR",   FuSa.Severity.ERROR.name());
        assertEquals("WARNING", FuSa.Severity.WARNING.name());
        assertEquals("INFO",    FuSa.Severity.INFO.name());
    }

    @Test
    void severity_inCheckJson_isUppercase() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("sev-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/T.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, "public class T { public String f() { return null; } }");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("LINT001"));
        Report report = new Report(result, cfg);
        String json = report.render("json");
        assertTrue(json.contains("\"WARNING\"") || json.contains("\"ERROR\"") || json.contains("\"INFO\""),
                "severity must be uppercase in JSON output");
        assertFalse(json.contains("\"warning\""), "lowercase severity not allowed");
        assertFalse(json.contains("\"error\""),   "lowercase severity not allowed");
    }

    // ── ruleId camelCase ───────────────────────────────────────────────────────

    @Test
    void finding_ruleId_isCamelCase_inJson() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("ruleid-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/T.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, "public class T { public String f() { return null; } }");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("LINT001"));
        Report report = new Report(result, cfg);
        String json = report.render("json");
        assertTrue(json.contains("\"ruleId\""), "JSON must use camelCase 'ruleId'");
        assertFalse(json.contains("\"rule_id\""), "snake_case 'rule_id' not allowed");
    }

    // ── nested location object ─────────────────────────────────────────────────

    @Test
    void finding_location_isNestedObject() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("loc-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/T.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, "public class T { public String f() { return null; } }");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("LINT001"));
        Report report = new Report(result, cfg);
        String json = report.render("json");
        // location must be a nested {"file":"…","line":N} object
        assertTrue(json.contains("\"location\""), "JSON must have location field");
        assertTrue(json.contains("\"file\""), "location must have file sub-field");
        assertTrue(json.contains("\"line\""), "location must have line sub-field");
    }

    // ── remediation field (not "fix") ──────────────────────────────────────────

    @Test
    void finding_hasRemediation_notFix() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("rem-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/T.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, "public class T { public String f() { return null; } }");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("LINT001"));
        Report report = new Report(result, cfg);
        String json = report.render("json");
        assertTrue(json.contains("\"remediation\""), "JSON must use 'remediation' field name");
        assertFalse(json.contains("\"fix\""), "'fix' is not the spec field name");
    }

    // ── fingerprint field ──────────────────────────────────────────────────────

    @Test
    void finding_hasFingerprint_sha256Prefixed() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("fp-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/T.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, "public class T { public String f() { return null; } }");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("LINT001"));
        assertFalse(result.findings().isEmpty());
        FuSa.Finding f = result.findings().get(0);
        assertTrue(f.fingerprint().startsWith("sha256:"), "fingerprint must be 'sha256:<hex>'");
        assertEquals(71, f.fingerprint().length(), "sha256: + 64 hex chars = 71");
    }

    // ── category field ─────────────────────────────────────────────────────────

    @Test
    void finding_hasCategory_inJson() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("cat-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/T.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, "public class T { public String f() { return null; } }");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("LINT001"));
        Report report = new Report(result, cfg);
        String json = report.render("json");
        assertTrue(json.contains("\"category\""), "JSON must include category field");
    }

    // ── standard + clause fields ───────────────────────────────────────────────

    @Test
    void finding_hasStandardAndClause_inJson() throws Exception {
        AnalyzeRules.activate();
        Config cfg = Config.defaultConfig("std-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/T.java");
        Files.createDirectories(src.getParent());
        // ANA001 always sets standard + clause
        Files.writeString(src, """
                public class T {
                    String bad(Object o) { return o.toString().toLowerCase(); }
                }
                """);
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("ANA001"));
        Report report = new Report(result, cfg);
        String json = report.render("json");
        assertTrue(json.contains("\"standard\""), "JSON must include standard field");
        assertTrue(json.contains("\"clause\""), "JSON must include clause field");
    }

    // ── exit codes ─────────────────────────────────────────────────────────────

    @Test
    void exitCode_2_forUsageErrors() {
        assertEquals(2, FuSa.EXIT_USAGE, "Usage error exit code must be 2");
    }

    @Test
    void exitCode_3_forRuntimeErrors() {
        assertEquals(3, FuSa.EXIT_RUNTIME, "Runtime error exit code must be 3");
    }

    @Test
    void exitCode_1_forGateFailures() {
        assertEquals(1, FuSa.EXIT_GATE_FAIL, "Gate failure exit code must be 1");
    }

    @Test
    void exitCode_0_forSuccess() {
        assertEquals(0, FuSa.EXIT_OK, "Success exit code must be 0");
    }

    // ── SBOM format ────────────────────────────────────────────────────────────

    @Test
    void sbom_kind_isSbom() throws Exception {
        Config cfg = Config.defaultConfig("sbom-test");
        Config.save(tmp, cfg);
        Release.generateSBOM(tmp, cfg);
        String content = Files.readString(tmp.resolve("sbom.json"));
        assertTrue(content.contains("\"kind\""), "sbom.json must have kind field");
        assertTrue(content.contains("\"sbom\""), "sbom.json kind must be 'sbom'");
        assertTrue(content.contains("\"schemaVersion\""), "sbom.json must have §3.1 schemaVersion");
        assertTrue(content.contains("\"module\""), "sbom.json must have module field");
        assertTrue(content.contains("\"components\""), "sbom.json must have components array");
    }

    // ── Evidence filenames ─────────────────────────────────────────────────────

    @Test
    void evidenceFilenames_areKebabCase() {
        assertEquals("sbom.json",            Release.SBOM_FILE);
        assertEquals("provenance.json",      Release.PROVENANCE_FILE);
        assertEquals("artifact-manifest.json", Release.MANIFEST_FILE);
    }

    // ── Gap-report kind for all 7 standards ───────────────────────────────────

    @Test
    void iso26262_gapReport_kindIsGapReport() throws Exception {
        Iso26262.generate(tmp, "ASIL-B");
        String content = Files.readString(tmp.resolve(Iso26262.GAP_REPORT));
        assertTrue(content.contains("\"gap-report\""), "iso26262 must emit kind='gap-report'");
        assertTrue(content.contains("\"iso26262\""), "iso26262 must have standard='iso26262'");
    }

    @Test
    void iec61508_gapReport_kindIsGapReport() throws Exception {
        Iec61508.generate(tmp, "SIL-2");
        String content = Files.readString(tmp.resolve(Iec61508.GAP_REPORT));
        assertTrue(content.contains("\"gap-report\""), "iec61508 must emit kind='gap-report'");
    }

    @Test
    void iso21434_gapReport_kindIsGapReport() throws Exception {
        Iso21434.generate(tmp, "CAL-2");
        String content = Files.readString(tmp.resolve(Iso21434.GAP_REPORT));
        assertTrue(content.contains("\"gap-report\""), "iso21434 must emit kind='gap-report'");
    }

    @Test
    void do178_gapReport_kindIsGapReport() throws Exception {
        Do178.generate(tmp, "DAL-B");
        String content = Files.readString(tmp.resolve(Do178.GAP_REPORT));
        assertTrue(content.contains("\"gap-report\""), "do178 must emit kind='gap-report'");
    }

    @Test
    void iec62443_gapReport_kindIsGapReport() throws Exception {
        Iec62443.generate(tmp, "SL-2");
        String content = Files.readString(tmp.resolve(Iec62443.GAP_REPORT));
        assertTrue(content.contains("\"gap-report\""), "iec62443 must emit kind='gap-report'");
        assertTrue(content.contains("\"iec62443\""), "iec62443 must have standard='iec62443'");
    }

    @Test
    void unece_gapReport_kindIsGapReport() throws Exception {
        Unece.generate(tmp);
        String content = Files.readString(tmp.resolve(Unece.GAP_REPORT));
        assertTrue(content.contains("\"gap-report\""), "unece must emit kind='gap-report'");
    }

    @Test
    void slsa_gapReport_standardIdIsSlsa() throws Exception {
        Slsa.generateGapReport(tmp, "L2", "json");
        String content = Files.readString(tmp.resolve(Slsa.SLSA_GAP_REPORT));
        assertTrue(content.contains("\"gap-report\""), "slsa must emit kind='gap-report'");
        assertTrue(content.contains("\"slsa\""), "slsa must emit standard='slsa'");
        assertFalse(content.contains("\"slsa-v1.0\""), "slsa standard id must not have version suffix");
    }

    // ── Format-invariant ids (§2.9) ────────────────────────────────────────────

    @Test
    void ids_ruleIdIdentical_acrossFormats() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("inv-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/T.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, "public class T { public String f() { return null; } }");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("LINT001"));
        if (result.findings().isEmpty()) return;
        Report report = new Report(result, cfg);
        String json = report.render("json");
        String text = report.render("text");
        assertTrue(json.contains("\"LINT001\""), "JSON must contain LINT001");
        assertTrue(text.contains("LINT001"), "text must contain LINT001");
    }

    @Test
    void ids_severityIdentical_acrossJsonAndSarif() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("sarif-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/T.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, "public class T { public String f() { return null; } }");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("LINT001"));
        if (result.findings().isEmpty()) return;
        Report report = new Report(result, cfg);
        String json = report.render("json");
        String sarif = report.render("sarif");
        // JSON: "severity":"WARNING", SARIF maps to level:"warning" (per SARIF spec §3.27.10)
        assertTrue(json.contains("\"WARNING\""), "JSON severity must be uppercase WARNING");
        assertTrue(sarif.contains("\"warning\""), "SARIF level must be lowercase warning for WARNING");
    }

    // ── location.file project-relative ────────────────────────────────────────

    @Test
    void location_file_isProjectRelative() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("rel-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/T.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, "public class T { public String f() { return null; } }");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("LINT001"));
        assertFalse(result.findings().isEmpty());
        FuSa.Finding f = result.findings().get(0);
        String file = f.location().file();
        assertFalse(file.startsWith("/"), "location.file must be project-relative, not absolute");
        assertTrue(file.contains("T.java"), "location.file must contain the filename");
    }

    // ── secTestedRequirements in trace JSON ────────────────────────────────────

    @Test
    void trace_coverage_hasSecTestedRequirements() throws Exception {
        Config cfg = Config.defaultConfig("sec-test");
        Config.save(tmp, cfg);
        com.soundmatt.jfusa.trace.Trace.activate();
        var matrix = com.soundmatt.jfusa.trace.Trace.buildMatrix(tmp, cfg);
        String json = com.soundmatt.jfusa.trace.Trace.renderJson(matrix);
        assertTrue(json.contains("\"secTestedRequirements\""),
                "trace JSON must include secTestedRequirements in coverage");
        assertTrue(json.contains("\"tracedRequirements\""),
                "trace JSON must include tracedRequirements in coverage");
        assertTrue(json.contains("\"testedRequirements\""),
                "trace JSON must include testedRequirements in coverage");
    }
}
