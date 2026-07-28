package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.trace.Trace;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class TraceTest {

    @TempDir Path tmp;

    // ── Feature 1: HLR/LLR hierarchy ─────────────────────────────────────────

    @Test
    //fusa:test REQ-HLR001
    void trace_loadFullRequirements_readsParentId() throws Exception {
        Path reqs = tmp.resolve(".fusa-reqs.json");
        Files.writeString(reqs, """
                {"schema":"x-fusa-reqs-1.0","requirements":[
                  {"id":"REQ-HLR","title":"High-level","status":"implemented"},
                  {"id":"REQ-LLR","title":"Low-level","parent_id":"REQ-HLR","status":"implemented"}
                ]}
                """);
        List<Trace.Requirement> loaded = Trace.loadFullRequirements(tmp);
        assertEquals(2, loaded.size());
        Trace.Requirement hlr = loaded.stream().filter(r -> r.id().equals("REQ-HLR")).findFirst().orElseThrow();
        Trace.Requirement llr = loaded.stream().filter(r -> r.id().equals("REQ-LLR")).findFirst().orElseThrow();
        assertTrue(hlr.isHlr(), "REQ-HLR should be HLR");
        assertFalse(hlr.isLlr(), "REQ-HLR should not be LLR");
        assertTrue(llr.isLlr(), "REQ-LLR should be LLR");
        assertEquals("REQ-HLR", llr.parentId());
    }

    @Test
    //fusa:test REQ-HLR002
    void trace_validateHierarchy_detectsOrphanLlr() {
        List<Trace.Requirement> reqs = List.of(
                new Trace.Requirement("REQ-HLR-A", "HLR", null),
                new Trace.Requirement("REQ-LLR-X", "LLR", "REQ-MISSING")  // unknown parent
        );
        Trace.HlrLlrResult result = Trace.validateHierarchy(reqs);
        assertTrue(result.hasViolations());
        assertTrue(result.orphanLlrs().contains("REQ-LLR-X"));
    }

    @Test
    //fusa:test REQ-HLR002
    void trace_validateHierarchy_detectsChildlessHlr() {
        List<Trace.Requirement> reqs = List.of(
                new Trace.Requirement("REQ-HLR-A", "HLR", null)  // no children
        );
        Trace.HlrLlrResult result = Trace.validateHierarchy(reqs);
        assertTrue(result.hasViolations());
        assertTrue(result.childlessHlrs().contains("REQ-HLR-A"));
    }

    @Test
    //fusa:test REQ-HLR002
    void trace_validateHierarchy_passesForValidHierarchy() {
        List<Trace.Requirement> reqs = List.of(
                new Trace.Requirement("REQ-HLR-A", "HLR", null),
                new Trace.Requirement("REQ-LLR-X", "LLR", "REQ-HLR-A")
        );
        Trace.HlrLlrResult result = Trace.validateHierarchy(reqs);
        assertFalse(result.hasViolations());
        assertTrue(result.orphanLlrs().isEmpty());
        assertTrue(result.childlessHlrs().isEmpty());
    }

    @Test
    //fusa:test REQ-HLR001
    void trace_renderText_withHlrResult_includesHierarchySection() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Map<String, List<Trace.Annotation>> matrix = Trace.buildMatrix(tmp, cfg);
        Trace.HlrLlrResult hlr = new Trace.HlrLlrResult(List.of(), List.of("REQ-HLR-A"), true);
        String text = Trace.renderText(matrix, hlr);
        assertTrue(text.contains("HLR/LLR Hierarchy"), "text should contain hierarchy section");
        assertTrue(text.contains("REQ-HLR-A"), "text should mention childless HLR");
    }

    @Test
    //fusa:test REQ-HLR001
    void trace_renderJson_withHlrResult_includesHierarchyObject() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Map<String, List<Trace.Annotation>> matrix = Trace.buildMatrix(tmp, cfg);
        Trace.HlrLlrResult hlr = new Trace.HlrLlrResult(List.of("REQ-LLR-X"), List.of(), true);
        String json = Trace.renderJson(matrix, tmp, hlr);
        assertTrue(json.contains("\"hierarchy\""), "JSON should include hierarchy object");
        assertTrue(json.contains("\"hasViolations\""), "JSON should include hasViolations");
        assertTrue(json.contains("REQ-LLR-X"), "JSON should list orphan LLR");
    }

    @Test
    //fusa:test REQ-HLR001
    void trace_loadFullRequirements_emptyWhenNoFile() {
        List<Trace.Requirement> reqs = Trace.loadFullRequirements(tmp);
        assertTrue(reqs.isEmpty(), "should return empty list when no .fusa-reqs.json");
    }

    @Test
    //fusa:test REQ-TRACE004
    void trace_scanAnnotations_findsReqAnnotation() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/Foo.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Foo {
                    //fusa:req REQ-001
                    public void method() {}
                }
                """);
        Path reqs = tmp.resolve(".fusa-reqs.json");
        Files.writeString(reqs, """
                {"schema":"x-fusa-reqs-1.0","requirements":[
                  {"id":"REQ-001","title":"first req","status":"implemented"}
                ]}
                """);
        List<Trace.Annotation> annotations = Trace.scanAnnotations(tmp, cfg);
        assertTrue(annotations.stream().anyMatch(a -> a.reqId().equals("REQ-001")),
                "Should find REQ-001 annotation");
    }

    @Test
    void trace_renderText_noAnnotations_notEmpty() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Map<String, List<Trace.Annotation>> matrix = Trace.buildMatrix(tmp, cfg);
        String text = Trace.renderText(matrix);
        assertNotNull(text);
        assertFalse(text.isBlank());
    }

    @Test
    void trace_renderJson_isValidJson() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Map<String, List<Trace.Annotation>> matrix = Trace.buildMatrix(tmp, cfg);
        String json = Trace.renderJson(matrix);
        assertTrue(json.startsWith("{"), "JSON must start with {");
        // §5 canonical shape
        assertTrue(json.contains("\"schemaVersion\""), "must have §3.1 schemaVersion");
        assertTrue(json.contains("\"kind\""), "must have §3.1 kind");
        assertTrue(json.contains("\"requirements\""), "must have §5 requirements[]");
        assertTrue(json.contains("\"tags\""), "must have §5 tags[]");
        assertTrue(json.contains("\"coverage\""), "must have §5 coverage");
        assertTrue(json.contains("\"secTestedRequirements\""), "must have secTestedRequirements");
    }

    @Test
    void trace_tagKind_isImpl_notReq() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/Impl.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Impl {
                    //fusa:req REQ-KIND
                    public void doThing() {}
                }
                """);
        List<Trace.Annotation> annotations = Trace.scanAnnotations(tmp, cfg);
        Trace.Annotation a = annotations.stream()
                .filter(x -> x.reqId().equals("REQ-KIND")).findFirst().orElseThrow();
        assertEquals("impl", a.type(), "//fusa:req must produce kind='impl', not 'req'");
    }

    @Test
    //fusa:test REQ-TRACE004
    void trace_renderJson_tagsHaveRequirementId() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/Impl.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Impl {
                    //fusa:req REQ-TAG
                    public void doThing() {}
                }
                """);
        Map<String, List<Trace.Annotation>> matrix = Trace.buildMatrix(tmp, cfg);
        String json = Trace.renderJson(matrix);
        assertTrue(json.contains("\"requirementId\""), "tags[] must use requirementId not reqId");
        assertTrue(json.contains("\"kind\""), "tags[] must have kind field");
        assertTrue(json.contains("\"impl\""), "kind must be 'impl' for //fusa:req annotations");
    }

    @Test
    //fusa:test REQ-TRACE001
    void trace_findGaps_withRequirementButNoTestAnnotation() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/Impl.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Impl {
                    //fusa:req REQ-GAP
                    public void doThing() {}
                }
                """);
        // No //fusa:test REQ-GAP anywhere
        List<String> gaps = Trace.findGaps(tmp, cfg);
        assertTrue(gaps.contains("REQ-GAP"),
                "REQ-GAP has source annotation but no test — should be a gap");
    }

    @Test
    //fusa:test REQ-TRACE001
    void trace_noGaps_whenTestAnnotationPresent() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/Impl.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Impl {
                    //fusa:req REQ-COVERED
                    //fusa:test REQ-COVERED
                    public void doThing() {}
                }
                """);
        List<String> gaps = Trace.findGaps(tmp, cfg);
        assertFalse(gaps.contains("REQ-COVERED"),
                "REQ-COVERED has both req and test — should not be a gap");
    }

    // ── §1.4.1 false-positive filtering: string-literal / text-block matches ──

    @Test
    void trace_scanAnnotations_ignoresStringLiteralMatches() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/Fixture.java");
        Files.createDirectories(src.getParent());
        // Mirrors this repo's own test-fixture pattern (e.g. Spec11ConformanceTest) of writing
        // example source as a string literal — the embedded "annotations" must not be scanned.
        Files.writeString(src, """
                public class Fixture {
                    void writeExample() {
                        String example = "embedded //fusa:req REQ-FAKE-001 example";
                        String note = "embedded //fusa:test REQ-FAKE-002 example";
                    }
                }
                """);
        List<Trace.Annotation> annotations = Trace.scanAnnotations(tmp, cfg);
        assertTrue(annotations.stream().noneMatch(a -> a.reqId().startsWith("REQ-FAKE")),
                "annotations embedded inside a string literal must be filtered out");
    }

    @Test
    void trace_scanAnnotations_ignoresTextBlockMatches() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/Fixture2.java");
        Files.createDirectories(src.getParent());
        // Mirrors this repo's own test-fixture pattern (e.g. TraceTest itself) of writing example
        // source as a multi-line text block — the embedded "annotation" must not be scanned.
        String fixtureSource =
                "public class Fixture2 {\n" +
                "    void writeExample() {\n" +
                "        String example = \"\"\"\n" +
                "                public class Foo {\n" +
                "                    //fusa:req REQ-FAKE-003\n" +
                "                    public void method() {}\n" +
                "                }\n" +
                "                \"\"\";\n" +
                "    }\n" +
                "}\n";
        Files.writeString(src, fixtureSource);
        List<Trace.Annotation> annotations = Trace.scanAnnotations(tmp, cfg);
        assertTrue(annotations.stream().noneMatch(a -> a.reqId().equals("REQ-FAKE-003")),
                "annotations embedded inside a multi-line text block must be filtered out");
    }

    // ── §1.4.1 / §5 --func-coverage ───────────────────────────────────────────

    @Test
    //fusa:test REQ-TRACE002
    void computeFuncCoverage_allTagged_100Percent() throws Exception {
        Config cfg = Config.defaultConfig("func-cov-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/Foo.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Foo {
                    //fusa:req REQ-A
                    public void doThing() {}
                }
                """);
        Trace.FuncCoverageResult result = Trace.computeFuncCoverage(tmp, cfg);
        assertEquals(1, result.totalFunctions());
        assertEquals(1, result.taggedFunctions());
        assertEquals(100.0, result.percentage(), 0.001);
    }

    @Test
    //fusa:test REQ-TRACE002
    void computeFuncCoverage_untaggedMethod_lowersPercentage() throws Exception {
        Config cfg = Config.defaultConfig("func-cov-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/Bar.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Bar {
                    //fusa:req REQ-B
                    public void tagged() {}
                    public void untagged() {}
                }
                """);
        Trace.FuncCoverageResult result = Trace.computeFuncCoverage(tmp, cfg);
        assertEquals(2, result.totalFunctions());
        assertEquals(1, result.taggedFunctions());
        assertEquals(50.0, result.percentage(), 0.001);
    }

    @Test
    //fusa:test REQ-TRACE002
    void computeFuncCoverage_exemptsGettersConstructorsAndNoOpShims() throws Exception {
        Config cfg = Config.defaultConfig("func-cov-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/main/java/Baz.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Baz {
                    public Baz() {}
                    public String id() { return "X"; }
                    public String description() { return "d"; }
                    public static void activate() {}
                    public String getName() { return "n"; }
                    public boolean isReady() { return true; }
                }
                """);
        Trace.FuncCoverageResult result = Trace.computeFuncCoverage(tmp, cfg);
        assertEquals(0, result.totalFunctions(),
                "constructors, id()/description()/activate() shims, and getters/setters must be exempt");
    }

    @Test
    //fusa:test REQ-TRACE002
    void computeFuncCoverage_noPublicFunctions_is100Percent() throws Exception {
        Config cfg = Config.defaultConfig("func-cov-test");
        Config.save(tmp, cfg);
        Trace.FuncCoverageResult result = Trace.computeFuncCoverage(tmp, cfg);
        assertEquals(0, result.totalFunctions());
        assertEquals(100.0, result.percentage(), 0.001,
                "no public functions to cover — gate must trivially pass");
    }

    /**
     * Regression test for x-FuSa/java-FuSa#33 (§1.6 rule 4, "real referents only"): a public
     * method declared only inside {@code src/test} must not be counted in the func-coverage
     * denominator — it is a test fixture, not a real project component. Without this exclusion,
     * fmea's coveragePct (which reuses this same denominator) can be pushed above 100%.
     */
    @Test
    //fusa:test REQ-TRACE005
    void computeFuncCoverage_excludesSrcTestTree() throws Exception {
        Config cfg = Config.defaultConfig("func-cov-test");
        Config.save(tmp, cfg);
        Path main = tmp.resolve("src/main/java/Widget.java");
        Files.createDirectories(main.getParent());
        Files.writeString(main, """
                public class Widget {
                    //fusa:req REQ-A
                    public void safeShutdown() {}
                }
                """);
        Path test = tmp.resolve("src/test/java/WidgetTest.java");
        Files.createDirectories(test.getParent());
        Files.writeString(test, """
                public class WidgetTest {
                    public void testFixtureMethod() {}
                }
                """);
        Trace.FuncCoverageResult result = Trace.computeFuncCoverage(tmp, cfg);
        assertEquals(1, result.totalFunctions(),
                "the src/test fixture method must be excluded from the denominator");
        assertEquals(1, result.taggedFunctions());
    }

    /**
     * Regression test for x-FuSa/java-FuSa#33: {@code scanComponentMethods} is the shared scan
     * fmea's derivation reuses (spec v1.15.0 §1.6 rule 4 implementer guidance) — it must expose
     * the real method's return type/params and must also exclude the src/test tree.
     */
    @Test
    //fusa:test REQ-TRACE005
    void scanComponentMethods_excludesTestTreeAndExposesSignature() throws Exception {
        Config cfg = Config.defaultConfig("func-cov-test");
        Config.save(tmp, cfg);
        Path main = tmp.resolve("src/main/java/Widget.java");
        Files.createDirectories(main.getParent());
        Files.writeString(main, """
                public class Widget {
                    public boolean validateInput(String s) { return true; }
                }
                """);
        Path test = tmp.resolve("src/test/java/WidgetTest.java");
        Files.createDirectories(test.getParent());
        Files.writeString(test, "public class WidgetTest {\n    public void fixture() {}\n}\n");

        List<Trace.ComponentMethod> methods = Trace.scanComponentMethods(tmp, cfg);
        assertEquals(1, methods.size());
        assertEquals("validateInput", methods.get(0).name());
        assertEquals("boolean", methods.get(0).returnType());
        assertEquals("String s", methods.get(0).params());
    }

    // ── §1.4.1 dangling test-reference detection (TRACE002 rule) ─────────────

    @Test
    //fusa:test REQ-TRACE003
    void danglingTestRef_firesForUnknownId() throws Exception {
        Trace.activate();
        Config cfg = Config.defaultConfig("dangling-test");
        Config.save(tmp, cfg);
        Files.writeString(tmp.resolve(".fusa-reqs.json"), """
                {"schema":"x-fusa-reqs-1.0","requirements":[
                  {"id":"REQ-KNOWN","title":"known req","status":"implemented"}
                ]}
                """);
        Path src = tmp.resolve("src/test/java/FooTest.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                class FooTest {
                    //fusa:test REQ-GHOST
                    void test() {}
                }
                """);
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("TRACE002"));
        assertTrue(result.findings().stream().anyMatch(f ->
                        f.ruleId().equals("TRACE002") && f.message().contains("REQ-GHOST")),
                "dangling //fusa:test id must produce a TRACE002 WARNING finding");
    }

    @Test
    //fusa:test REQ-TRACE003
    void danglingTestRef_doesNotFireForKnownId() throws Exception {
        Trace.activate();
        Config cfg = Config.defaultConfig("dangling-test");
        Config.save(tmp, cfg);
        Files.writeString(tmp.resolve(".fusa-reqs.json"), """
                {"schema":"x-fusa-reqs-1.0","requirements":[
                  {"id":"REQ-KNOWN","title":"known req","status":"implemented"}
                ]}
                """);
        Path src = tmp.resolve("src/test/java/FooTest.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                class FooTest {
                    //fusa:test REQ-KNOWN
                    void test() {}
                }
                """);
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("TRACE002"));
        assertTrue(result.findings().isEmpty(), "known requirement id must not be flagged as dangling");
    }

    @Test
    //fusa:test REQ-TRACE003
    void danglingTestRef_skipsWhenNoReqsFile() throws Exception {
        Trace.activate();
        Config cfg = Config.defaultConfig("dangling-test");
        Config.save(tmp, cfg);
        Path src = tmp.resolve("src/test/java/FooTest.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                class FooTest {
                    //fusa:test REQ-ANYTHING
                    void test() {}
                }
                """);
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("TRACE002"));
        assertTrue(result.findings().isEmpty(), "without .fusa-reqs.json there is nothing to validate against");
    }

    // ── Regression: escaped quotes in .fusa-reqs.json titles (issue #28) ─────

    @Test
    //fusa:test REQ-TRACE-JSON001
    void renderJson_handlesEscapedQuoteInTitleWithoutCorruptingLaterEntries() throws Exception {
        Path reqs = tmp.resolve(".fusa-reqs.json");
        Files.writeString(reqs, """
                {"requirements":[
                  {"id":"REQ-001","title":"@SuppressWarnings(\\"unchecked\\") usage must be flagged","standard":"generic"},
                  {"id":"REQ-002","title":"Second requirement","standard":"generic"}
                ]}
                """);
        Map<String, List<Trace.Annotation>> matrix = new java.util.LinkedHashMap<>();
        matrix.put("REQ-001", List.of(new Trace.Annotation("REQ-001", "Main.java", 1, "impl")));
        matrix.put("REQ-002", List.of(new Trace.Annotation("REQ-002", "Main.java", 2, "impl")));

        String json = Trace.renderJson(matrix, tmp);

        // Must be valid, parseable JSON -- the original bug corrupted every
        // entry after the one with an escaped quote in its title.
        Map<String, Object> doc = assertDoesNotThrow(() -> com.soundmatt.jfusa.internal.Json.parseObject(json));
        List<Object> requirements = com.soundmatt.jfusa.internal.Json.arr(doc, "requirements");
        assertEquals(2, requirements.size());

        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) requirements.get(0);
        assertEquals("REQ-001", first.get("id"));
        assertEquals("@SuppressWarnings(\"unchecked\") usage must be flagged", first.get("title"));

        @SuppressWarnings("unchecked")
        Map<String, Object> second = (Map<String, Object>) requirements.get(1);
        assertEquals("REQ-002", second.get("id"));
        assertEquals("Second requirement", second.get("title"), "entry after the escaped quote must not be corrupted");
    }
}
