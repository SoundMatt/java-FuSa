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
