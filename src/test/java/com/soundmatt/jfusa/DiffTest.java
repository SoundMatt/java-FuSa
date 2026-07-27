package com.soundmatt.jfusa;

import com.soundmatt.jfusa.diff.Diff;
import com.soundmatt.jfusa.internal.Json;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class DiffTest {

    @TempDir Path tmp;

    //fusa:test REQ-DIFF001
    @Test
    void diff_identical_reports_noChanges() throws Exception {
        String json = buildReport("LINT001", "return null without annotation", "Foo.java");
        Path a = tmp.resolve("a.json"); Path b = tmp.resolve("b.json");
        Files.writeString(a, json); Files.writeString(b, json);
        Diff.DiffResult r = Diff.compare(a, b);
        assertTrue(r.introduced().isEmpty(), "No introduced findings if reports are identical");
        assertTrue(r.resolved().isEmpty(), "No resolved findings if reports are identical");
        assertFalse(r.unchanged().isEmpty(), "Unchanged should contain the finding");
    }

    //fusa:test REQ-DIFF001
    @Test
    void diff_detects_introduced_finding() throws Exception {
        String empty = "{\"schema\":\"x-fusa-1.9\",\"findings\":[]}";
        String withFinding = buildReport("LINT001", "return null", "Foo.java");
        Path a = tmp.resolve("a.json"); Path b = tmp.resolve("b.json");
        Files.writeString(a, empty); Files.writeString(b, withFinding);
        Diff.DiffResult r = Diff.compare(a, b);
        assertFalse(r.introduced().isEmpty(), "Should detect introduced finding");
        assertTrue(r.resolved().isEmpty());
    }

    //fusa:test REQ-DIFF001
    @Test
    void diff_detects_resolved_finding() throws Exception {
        String withFinding = buildReport("LINT001", "return null", "Foo.java");
        String empty = "{\"schema\":\"x-fusa-1.9\",\"findings\":[]}";
        Path a = tmp.resolve("a.json"); Path b = tmp.resolve("b.json");
        Files.writeString(a, withFinding); Files.writeString(b, empty);
        Diff.DiffResult r = Diff.compare(a, b);
        assertTrue(r.introduced().isEmpty());
        assertFalse(r.resolved().isEmpty(), "Should detect resolved finding");
    }

    //fusa:test REQ-DIFF001
    @Test
    void diff_renderText_containsSummary() throws Exception {
        String empty = "{\"schema\":\"x-fusa-1.9\",\"findings\":[]}";
        Path a = tmp.resolve("a.json"); Path b = tmp.resolve("b.json");
        Files.writeString(a, empty); Files.writeString(b, empty);
        Diff.DiffResult r = Diff.compare(a, b);
        String text = Diff.renderText(r, "a.json", "b.json");
        assertNotNull(text);
        assertTrue(text.contains("Introduced"));
        assertTrue(text.contains("Resolved"));
    }

    //fusa:test REQ-DIFF001
    @Test
    void diff_hasIntroduced_false_whenEmpty() throws Exception {
        String empty = "{\"schema\":\"x-fusa-1.9\",\"findings\":[]}";
        Path a = tmp.resolve("a.json"); Path b = tmp.resolve("b.json");
        Files.writeString(a, empty); Files.writeString(b, empty);
        Diff.DiffResult r = Diff.compare(a, b);
        assertFalse(r.hasIntroduced());
    }

    static String buildReport(String ruleId, String msg, String file) {
        FuSa.Finding f = FuSa.Finding.builder(ruleId, FuSa.Severity.WARNING,
                msg, new FuSa.Location(file, 1)).build();
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-1.9");
        w.key("findings"); w.arrayStart();
        w.objectStart();
        w.field("fingerprint", f.fingerprint());
        w.field("ruleId", ruleId);
        w.field("message", msg);
        w.objectEnd();
        w.arrayEnd();
        w.objectEnd();
        return w.toString();
    }
}
