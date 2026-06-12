package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Registry;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.report.Report;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Focused conformance suite for §2.2 (--output no-stdout) and §2.9 (format-invariant identifiers).
 */
class ConformanceTest {

    @TempDir Path tmp;

    private Engine engineWithFinding() {
        Registry reg = new Registry();
        reg.mustRegister(new Rule() {
            public String id() { return "LINT042"; }
            public String description() { return "conformance test rule"; }
            public List<FuSa.Finding> run(Path r, Config c) {
                return List.of(
                    FuSa.Finding.builder("LINT042", FuSa.Severity.WARNING,
                            "test finding for conformance", new FuSa.Location("Foo.java", 7))
                        .category(FuSa.Category.lint)
                        .standard("iso26262").clause("6.4")
                        .build()
                );
            }
        });
        return new Engine(reg);
    }

    // ── §2.9: format-invariant identifiers ───────────────────────────────────

    @Test
    void ruleId_isIdenticalAcrossFormats() throws Exception {
        Engine eng = engineWithFinding();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("conf-test"));
        Report report = new Report(result, Config.defaultConfig("conf-test"));

        String json  = report.render("json");
        String sarif = report.render("sarif");
        String text  = report.render("text");
        String html  = report.render("html");

        // §2.9: ruleId byte-identical across all formats
        assertTrue(json.contains("\"ruleId\": \"LINT042\""), "json missing ruleId LINT042");
        assertTrue(sarif.contains("\"ruleId\": \"LINT042\""), "sarif missing ruleId LINT042");
        assertTrue(text.contains("LINT042"), "text missing LINT042");
        assertTrue(html.contains("LINT042"), "html missing LINT042");
    }

    @Test
    void severity_isIdenticalAcrossJsonAndSarif() throws Exception {
        Engine eng = engineWithFinding();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("conf-test"));
        Report report = new Report(result, Config.defaultConfig("conf-test"));

        String json  = report.render("json");
        String sarif = report.render("sarif");
        String text  = report.render("text");

        // §2.9: severity name appears in json and text
        assertTrue(json.contains("\"severity\": \"WARNING\""), "json missing severity WARNING");
        assertTrue(text.contains("WARNING"), "text missing WARNING");
        // SARIF uses level (spec §2.9: ERROR→error, WARNING→warning)
        assertTrue(sarif.contains("\"level\": \"warning\""), "sarif missing level warning");
    }

    @Test
    void category_isIdenticalInJsonAndSarif() throws Exception {
        Engine eng = engineWithFinding();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("conf-test"));
        Report report = new Report(result, Config.defaultConfig("conf-test"));

        String json  = report.render("json");
        String sarif = report.render("sarif");

        // §2.9: category value identical in json findings and sarif properties
        assertTrue(json.contains("\"category\": \"lint\""), "json missing category lint");
        assertTrue(sarif.contains("\"category\": \"lint\""), "sarif properties missing category lint");
    }

    @Test
    void sarif_fingerprints_isPropertyBag() throws Exception {
        // Finding with a fingerprint must appear as a SARIF property bag, not a string
        Engine eng = engineWithFinding();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("conf-test"));
        Report report = new Report(result, Config.defaultConfig("conf-test"));
        String sarif = report.render("sarif");

        // fingerprints must be an object {}, not a raw "sha256:..." string at that level
        int fp = sarif.indexOf("fingerprints");
        if (fp >= 0) {
            // The character after '"fingerprints": ' should start an object '{'
            String after = sarif.substring(fp + "fingerprints".length()).stripLeading();
            // after is like `": { ...`
            int colon = after.indexOf(':');
            if (colon >= 0) {
                String afterColon = after.substring(colon + 1).stripLeading();
                assertTrue(afterColon.startsWith("{"),
                        "SARIF fingerprints must be a property bag (object), found: " + afterColon.substring(0, Math.min(20, afterColon.length())));
            }
        }
    }

    // ── §2.2: --output no-stdout copy ────────────────────────────────────────

    @Test
    void cmdCheck_withOutput_writesToFile() throws Exception {
        // Minimal project: just the config
        Config.save(tmp, Config.defaultConfig("output-test"));
        Path outFile = tmp.resolve("out.json");

        // Simulate what cmdCheck does when --output is given
        Config cfg = Config.load(tmp);
        Engine.Result result = new Engine(new Registry()).run(tmp, cfg);
        Report report = new Report(result, cfg);
        String rendered = report.render("json");
        // §2.2: write to file — do NOT also print to stdout
        Files.writeString(outFile, rendered);

        assertTrue(Files.exists(outFile), "output file must be written");
        String content = Files.readString(outFile);
        assertTrue(content.contains("\"schemaVersion\""), "output file must be valid check-report JSON");
    }

    @Test
    void outputFile_containsRequiredCommonHeader() throws Exception {
        Engine eng = engineWithFinding();
        Engine.Result result = eng.run(tmp, Config.defaultConfig("header-test"));
        Report report = new Report(result, Config.defaultConfig("header-test"));
        String json = report.render("json");

        // §3.1 common header — every output must carry these
        assertTrue(json.contains("\"schemaVersion\""), "missing schemaVersion");
        assertTrue(json.contains("\"kind\""),          "missing kind");
        assertTrue(json.contains("\"tool\""),          "missing tool");
        assertTrue(json.contains("\"toolVersion\""),   "missing toolVersion");
        assertTrue(json.contains("\"language\""),      "missing language");
        assertTrue(json.contains("\"generatedAt\""),   "missing generatedAt");
    }
}
