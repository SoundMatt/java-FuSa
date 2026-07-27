package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Registry;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.report.Report;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ReportTest {

    @TempDir Path tmp;

    Engine engineWithFindings() {
        Registry reg = new Registry();
        reg.mustRegister(new Rule() {
            public String id() { return "TEST001"; }
            public String description() { return "test rule"; }
            public List<FuSa.Finding> run(Path r, Config c) {
                return List.of(
                    FuSa.Finding.builder("TEST001", FuSa.Severity.ERROR,
                            "an error finding", new FuSa.Location("Foo.java", 5)).build(),
                    FuSa.Finding.builder("TEST001", FuSa.Severity.WARNING,
                            "a warning finding", new FuSa.Location("Bar.java", 10)).build(),
                    FuSa.Finding.builder("TEST001", FuSa.Severity.INFO,
                            "an info finding", new FuSa.Location("Baz.java", 15)).build()
                );
            }
        });
        return new Engine(reg);
    }

    //fusa:test REQ-REPORT001
    //fusa:test REQ-REPORT005
    @Test
    void textRender_containsFindingMessages() throws Exception {
        Engine eng = engineWithFindings();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("rpt-test"));
        Report report = new Report(result, Config.defaultConfig("rpt-test"));
        String text = report.render("text");
        assertTrue(text.contains("an error finding"));
        assertTrue(text.contains("a warning finding"));
    }

    //fusa:test REQ-REPORT001
    //fusa:test REQ-REPORT005
    @Test
    void jsonRender_isValidJson() throws Exception {
        Engine eng = engineWithFindings();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("rpt-test"));
        Report report = new Report(result, Config.defaultConfig("rpt-test"));
        String json = report.render("json");
        assertTrue(json.contains("\"findings\""));
        assertTrue(json.contains("\"schemaVersion\""));  // §3.1 common header
        assertTrue(json.startsWith("{"));
    }

    //fusa:test REQ-REPORT001
    //fusa:test REQ-REPORT005
    @Test
    void htmlRender_containsHtmlStructure() throws Exception {
        Engine eng = engineWithFindings();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("rpt-test"));
        Report report = new Report(result, Config.defaultConfig("rpt-test"));
        String html = report.render("html");
        assertTrue(html.contains("<!DOCTYPE html>"));
        assertTrue(html.contains("an error finding"));
    }

    //fusa:test REQ-REPORT001
    //fusa:test REQ-REPORT005
    @Test
    void sarifRender_hasRequiredFields() throws Exception {
        Engine eng = engineWithFindings();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("rpt-test"));
        Report report = new Report(result, Config.defaultConfig("rpt-test"));
        String sarif = report.render("sarif");
        assertTrue(sarif.contains("\"$schema\""));
        assertTrue(sarif.contains("2.1.0"));
        assertTrue(sarif.contains("\"runs\""));
    }

    //fusa:test REQ-REPORT002
    @Test
    void reportCounts_matchFindings() throws Exception {
        Engine eng = engineWithFindings();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("rpt-test"));
        Report report = new Report(result, Config.defaultConfig("rpt-test"));
        assertEquals(1, report.errors().size());
        assertEquals(1, report.warnings().size());
        assertEquals(1, report.infos().size());
    }

    //fusa:test REQ-REPORT003
    @Test
    void summary_containsCounts() throws Exception {
        Engine eng = engineWithFindings();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("rpt-test"));
        Report report = new Report(result, Config.defaultConfig("rpt-test"));
        String summary = report.summary();
        assertTrue(summary.contains("1 error"));
        assertTrue(summary.contains("1 warning"));
    }

    //fusa:test REQ-REPORT004
    @Test
    void categoryBreakdown_countsFindingsPerCategory() throws Exception {
        Engine eng = engineWithFindings();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("rpt-test"));
        Report report = new Report(result, Config.defaultConfig("rpt-test"));
        var breakdown = report.categoryBreakdown();
        long total = breakdown.values().stream().mapToLong(Long::longValue).sum();
        assertEquals(3, total);
    }
}
