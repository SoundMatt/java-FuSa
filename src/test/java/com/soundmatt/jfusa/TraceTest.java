package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.trace.Trace;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
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
        Trace trace = new Trace(tmp, cfg);
        var annotations = trace.scanAnnotations();
        assertTrue(annotations.stream().anyMatch(a -> a.target().equals("REQ-001")),
                "Should find REQ-001 annotation");
    }

    @Test
    void trace_renderText_noAnnotations_notEmpty() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Trace trace = new Trace(tmp, cfg);
        String text = trace.renderText();
        assertNotNull(text);
        assertFalse(text.isBlank());
    }

    @Test
    void trace_renderJson_isValidJson() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Trace trace = new Trace(tmp, cfg);
        String json = trace.renderJson();
        assertTrue(json.startsWith("{"));
        assertTrue(json.contains("\"schema\""));
    }

    @Test
    void trace_findGaps_withUnimplementedReq() throws Exception {
        Config cfg = Config.defaultConfig("trace-test");
        Config.save(tmp, cfg);
        Path reqs = tmp.resolve(".fusa-reqs.json");
        Files.writeString(reqs, """
                {"schema":"x-fusa-reqs-1.0","requirements":[
                  {"id":"REQ-GAP","title":"unimplemented","status":"open"}
                ]}
                """);
        Trace trace = new Trace(tmp, cfg);
        var gaps = trace.findGaps();
        assertTrue(gaps.stream().anyMatch(g -> g.contains("REQ-GAP")),
                "REQ-GAP has no annotation, should be reported as gap");
    }
}
