package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.qualify.Qualify;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class QualifyTest {

    @TempDir Path tmp;

    // ── Feature 2: Tool Qualification Display ─────────────────────────────────

    @Test
    //fusa:test REQ-QUALIFY002
    void qualify_badge_independentlyQualified() {
        Qualify.QualifyOptions opts = new Qualify.QualifyOptions(
                "independent", "Acme Corp", "https://example.com/dossier",
                "", "", "", "");
        assertEquals("independently-qualified", opts.badge());
    }

    @Test
    //fusa:test REQ-QUALIFY002
    void qualify_badge_selfQualified() {
        Qualify.QualifyOptions opts = new Qualify.QualifyOptions(
                "self", "", "", "", "", "", "");
        assertEquals("self-qualified", opts.badge());
    }

    @Test
    //fusa:test REQ-QUALIFY002
    void qualify_badge_unqualified_whenNoMethod() {
        Qualify.QualifyOptions opts = Qualify.QualifyOptions.empty();
        assertEquals("unqualified", opts.badge());
    }

    @Test
    //fusa:test REQ-QUALIFY002
    void qualify_reportContainsQualificationMethod() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.QualifyOptions opts = new Qualify.QualifyOptions(
                "independent", "SafetyOrg", "https://example.com/q",
                "", "", "", "");
        Qualify.run(tmp, cfg, false, opts);
        String content = Files.readString(tmp.resolve("qualify-report.json"));
        assertTrue(content.contains("\"qualificationMethod\""));
        assertTrue(content.contains("\"independently-qualified\""));
        assertTrue(content.contains("SafetyOrg"));
    }

    @Test
    //fusa:test REQ-QUALIFY002
    void qualify_reportContainsRecordUri() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.QualifyOptions opts = new Qualify.QualifyOptions(
                "self", "", "https://records.example.com/q-001",
                "", "", "", "");
        Qualify.run(tmp, cfg, false, opts);
        String content = Files.readString(tmp.resolve("qualify-report.json"));
        assertTrue(content.contains("qualificationRecordUri"));
        assertTrue(content.contains("https://records.example.com/q-001"));
    }

    // ── Feature 4: V&V Independence ───────────────────────────────────────────

    @Test
    //fusa:test REQ-QUALIFY003
    void qualify_independenceStatus_independentWhenDifferentPeople() {
        Qualify.QualifyOptions opts = new Qualify.QualifyOptions(
                "", "", "", "Alice", "Bob", "Carol", "ASIL-C");
        assertEquals("independent", opts.independenceStatus());
    }

    @Test
    //fusa:test REQ-QUALIFY003
    void qualify_independenceStatus_notIndependentWhenSamePerson() {
        Qualify.QualifyOptions opts = new Qualify.QualifyOptions(
                "", "", "", "Alice", "Alice", "Carol", "ASIL-B");
        assertEquals("not-independent", opts.independenceStatus());
    }

    @Test
    //fusa:test REQ-QUALIFY003
    void qualify_independenceStatus_notIndependentWhenBlankReviewer() {
        Qualify.QualifyOptions opts = new Qualify.QualifyOptions(
                "", "", "", "Alice", "", "", "");
        assertEquals("not-independent", opts.independenceStatus());
    }

    @Test
    //fusa:test REQ-QUALIFY003
    void qualify_reportContainsIndependenceFields() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.QualifyOptions opts = new Qualify.QualifyOptions(
                "independent", "AuditFirm", "",
                "Alice", "Bob", "Carol", "ASIL-B");
        Qualify.run(tmp, cfg, false, opts);
        String content = Files.readString(tmp.resolve("qualify-report.json"));
        assertTrue(content.contains("\"implementationAuthor\""));
        assertTrue(content.contains("Alice"));
        assertTrue(content.contains("\"independentReviewer\""));
        assertTrue(content.contains("Bob"));
        assertTrue(content.contains("\"independenceStatus\""));
        assertTrue(content.contains("\"independent\""));
    }

    @Test
    //fusa:test REQ-QUALIFY003
    void qualify_reportHasAchievableAsil() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.QualifyOptions opts = new Qualify.QualifyOptions(
                "", "", "", "Alice", "Bob", "", "ASIL-D");
        Qualify.run(tmp, cfg, false, opts);
        String content = Files.readString(tmp.resolve("qualify-report.json"));
        assertTrue(content.contains("\"achievableAsil\""));
        assertTrue(content.contains("ASIL-D"));
    }

    @Test
    //fusa:test REQ-QUALIFY001
    //fusa:test REQ-QUALIFY004
    void qualify_generatesReport() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.run(tmp, cfg, false);
        Path report = tmp.resolve("qualify-report.json");
        assertTrue(Files.exists(report), "qualify-report.json should be generated");
    }

    @Test
    //fusa:test REQ-QUALIFY001
    void qualify_reportContainsPassStatus() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.run(tmp, cfg, false);
        String content = Files.readString(tmp.resolve("qualify-report.json"));
        assertTrue(content.contains("\"schemaVersion\""));
        assertTrue(content.contains("TC-001"));
    }

    @Test
    //fusa:test REQ-QUALIFY001
    void qualify_reportHasIntegrityHash() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.run(tmp, cfg, false);
        String content = Files.readString(tmp.resolve("qualify-report.json"));
        Path hashFile = tmp.resolve("qualify-report.sha256");
        assertTrue(Files.exists(hashFile) || content.contains("sha256"),
                "qualify report should contain integrity hash");
    }

    @Test
    //fusa:test REQ-QUALIFY006
    void generateReport_honorsExplicitOutputPath() throws Exception {
        var cases = Qualify.runSelfTests();
        String content = Qualify.generateReport(tmp, cases, Qualify.QualifyOptions.empty(), "custom-name.json");
        assertTrue(Files.exists(tmp.resolve("custom-name.json")),
                "generateReport should write to the explicit output path");
        assertFalse(Files.exists(tmp.resolve("qualify-report.json")),
                "generateReport must not also write the default qualify-report.json");
        assertTrue(Files.exists(tmp.resolve("custom-name.sha256")),
                "the sibling sha256 hash file should be named after the actual output, not the default");
        assertTrue(content.contains("\"schemaVersion\""));
    }

    @Test
    //fusa:test REQ-QUALIFY006
    void run_withJsonFormat_writesConfiguredOutputAndDoesNotWriteDefault() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.run(tmp, cfg, false, Qualify.QualifyOptions.empty(), "q-out.json", "json");
        assertTrue(Files.exists(tmp.resolve("q-out.json")));
        assertFalse(Files.exists(tmp.resolve("qualify-report.json")));
    }

    @Test
    //fusa:test REQ-QUALIFY005
    void generateReport_backwardCompatOverload_writesReportWithoutOptions() throws Exception {
        var cases = Qualify.runSelfTests();
        Qualify.generateReport(tmp, cases);
        Path report = tmp.resolve("qualify-report.json");
        assertTrue(Files.exists(report), "qualify-report.json should be generated by the 2-arg overload");
        String content = Files.readString(report);
        assertTrue(content.contains("\"qualificationBadge\""));
        assertTrue(content.contains("\"unqualified\""),
                "2-arg overload should default to empty QualifyOptions");
    }
}
