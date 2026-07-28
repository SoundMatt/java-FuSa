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

    private void writeTestJavaFile(String name, String content) throws Exception {
        Path srcDir = tmp.resolve("src/test/java");
        Files.createDirectories(srcDir);
        Files.writeString(srcDir.resolve(name), content);
    }

    /** Direct unit test for the defensive clamp itself (x-FuSa spec v1.15.0 §9.2 MUST), independent
     *  of whatever the scanner invariant currently guarantees — belt-and-braces per the issue. */
    @Test
    //fusa:test REQ-FMEA007
    void clampCoveragePct_neverExceeds100() {
        assertEquals(100.0, Fmea.clampCoveragePct(111.9));
        assertEquals(87.5, Fmea.clampCoveragePct(87.5));
        assertEquals(100.0, Fmea.clampCoveragePct(100.0));
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

    /**
     * Regression test for x-FuSa/java-FuSa#33: a project with a non-trivial {@code src/test} tree
     * — including a text-block string literal that itself contains method-declaration-shaped text,
     * duplicated across two test methods — must not inflate {@code componentsAnalyzed} past
     * {@code componentsInProject}, and test-fixture classes must never appear as FMEA entries
     * (§1.6 rule 4, "real referents only"). A fixture with no {@code src/test}-equivalent directory
     * cannot exercise this bug — see the spec note this test is named after.
     */
    @Test
    //fusa:test REQ-FMEA002
    void build_nonTrivialTestTree_neverExceeds100PctAndExcludesTestFixtures() throws Exception {
        writeJavaFile("Widget.java", """
                public class Widget {
                    public void safeShutdown() {}
                    public boolean validateInput(String s) { return true; }
                }
                """);
        String fixtureBlock = """
                    void scenarioOne() {
                        String snippet = \"\"\"
                                public void safeShutdown() {}
                                public boolean validateInput(String s) { return true; }
                                public int processData() { return 0; }
                                \"\"\";
                    }

                    void scenarioTwo() {
                        String snippet = \"\"\"
                                public void safeShutdown() {}
                                public boolean validateInput(String s) { return true; }
                                public int processData() { return 0; }
                                \"\"\";
                    }
                """;
        writeTestJavaFile("WidgetTest.java", "public class WidgetTest {\n" + fixtureBlock + "}\n");

        Config cfg = Config.defaultConfig("fmea-test");
        Fmea.FmeaReport report = Fmea.build(tmp, cfg);

        assertTrue(report.summary().coveragePct() <= 100.0,
                "coveragePct must never exceed 100 (x-FuSa spec §9.2 MUST)");
        assertTrue(report.summary().componentsInProject() >= report.summary().componentsAnalyzed());
        assertTrue(report.entries().stream().noneMatch(e -> e.component().equals("WidgetTest")),
                "a src/test fixture class must never be counted as a real project component");
        assertEquals(2, report.entries().size(),
                "only Widget's two real public methods should be counted, not the duplicated text-block fixture");
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
