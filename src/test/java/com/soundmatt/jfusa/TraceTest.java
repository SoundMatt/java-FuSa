package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
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
}
