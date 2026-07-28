package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.fmea.Fmea;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FmeaTest {

    @TempDir Path tmp;

    private void writeJavaFile(String name, String content) throws Exception {
        Path srcDir = tmp.resolve("src/main/java");
        Files.createDirectories(srcDir);
        Files.writeString(srcDir.resolve(name), content);
    }

    @Test
    //fusa:test REQ-FMEA002
    void build_computesCoverageAgainstTraceFuncCoverageDenominator() throws Exception {
        writeJavaFile("Widget.java", """
                public class Widget {
                    public void safeShutdown() {}
                    public boolean validateInput(String s) { return true; }
                    public int processData() { return 0; }
                }
                """);
        Config cfg = Config.defaultConfig("fmea-test");
        Fmea.FmeaReport report = Fmea.build(tmp, cfg);
        assertEquals(report.entries().size(), report.summary().componentsAnalyzed());
        assertTrue(report.summary().componentsInProject() >= report.summary().componentsAnalyzed());
        assertTrue(report.summary().coveragePct() <= 100.0);
        assertFalse(report.summary().componentsInventoryMethod().isBlank());
    }

    @Test
    //fusa:test REQ-FMEA006
    void failureModeAndEffect_varyWithMethodSignature_notOneFixedString() throws Exception {
        writeJavaFile("Multi.java", """
                public class Multi {
                    public void doVoid() {}
                    public boolean doBool() { return true; }
                    public int doInt() { return 1; }
                    public String doString() { return ""; }
                }
                """);
        Config cfg = Config.defaultConfig("fmea-test");
        List<Fmea.FailureMode> entries = Fmea.derive(tmp, cfg);
        long distinctFailureModes = entries.stream().map(Fmea.FailureMode::failureMode).distinct().count();
        assertEquals(entries.size(), distinctFailureModes,
                "every entry's failureMode should be distinct — content must vary with the real signature");
    }

    @Test
    //fusa:test REQ-FMEA006
    void qualityBarFields_coverFailureModeEffectAndCause() throws Exception {
        writeJavaFile("One.java", "public class One {\n    public void doThing() {}\n}\n");
        Config cfg = Config.defaultConfig("fmea-test");
        List<Fmea.FailureMode> entries = Fmea.derive(tmp, cfg);
        var fields = Fmea.qualityBarFields(entries);
        assertEquals(entries.size() * 3, fields.size());
        assertTrue(fields.stream().anyMatch(f -> f.fieldName().equals("failureMode")));
        assertTrue(fields.stream().anyMatch(f -> f.fieldName().equals("effect")));
        assertTrue(fields.stream().anyMatch(f -> f.fieldName().equals("cause")));
    }

    @Test
    //fusa:test REQ-FMEA003
    void writeJson_respectsCustomOutputPath() throws Exception {
        writeJavaFile("Two.java", "public class Two {\n    public void act() {}\n}\n");
        Config cfg = Config.defaultConfig("fmea-test");
        Fmea.FmeaReport report = Fmea.build(tmp, cfg);
        Fmea.writeJson(tmp, report, "custom-fmea.json");
        assertTrue(Files.exists(tmp.resolve("custom-fmea.json")));
        assertFalse(Files.exists(tmp.resolve(Fmea.FMEA_JSON)));
    }

    @Test
    //fusa:test REQ-FMEA002
    void build_carriesForwardExistingAttestation() throws Exception {
        writeJavaFile("Three.java", "public class Three {\n    public void act() {}\n}\n");
        Config cfg = Config.defaultConfig("fmea-test");
        Files.writeString(tmp.resolve(Fmea.FMEA_JSON), """
                {"attestation": {"status":"reviewed","implementationAuthor":"auto",
                 "independentReviewer":"Jane Doe","reviewedAt":"2026-07-28T00:00:00Z",
                 "contentHash":"sha256:doesnotmatter"}}
                """);
        Fmea.FmeaReport report = Fmea.build(tmp, cfg);
        assertNotNull(report.attestation());
        assertEquals("Jane Doe", report.attestation().independentReviewer());
    }

    @Test
    //fusa:test REQ-FMEA004
    void renderText_includesCoverageAndEntries() throws Exception {
        writeJavaFile("Four.java", "public class Four {\n    public void act() {}\n}\n");
        Config cfg = Config.defaultConfig("fmea-test");
        Fmea.FmeaReport report = Fmea.build(tmp, cfg);
        String text = Fmea.renderText(report);
        assertTrue(text.contains("dFMEA"));
        assertTrue(text.contains("Failure mode:"));
    }

    @Test
    //fusa:test REQ-FMEA001
    void derive_excludesGettersSettersAndShims() throws Exception {
        writeJavaFile("Beans.java", """
                public class Beans {
                    public String getName() { return ""; }
                    public boolean isReady() { return true; }
                    public void setName(String n) {}
                    public void activate() {}
                    public void doRealWork() {}
                }
                """);
        Config cfg = Config.defaultConfig("fmea-test");
        List<Fmea.FailureMode> entries = Fmea.derive(tmp, cfg);
        assertTrue(entries.stream().noneMatch(e -> e.method().equals("getName")));
        assertTrue(entries.stream().noneMatch(e -> e.method().equals("isReady")));
        assertTrue(entries.stream().noneMatch(e -> e.method().equals("setName")));
        assertTrue(entries.stream().noneMatch(e -> e.method().equals("activate")));
        assertTrue(entries.stream().anyMatch(e -> e.method().equals("doRealWork")));
    }
}
