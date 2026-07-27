package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Registry;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.lint.LintRules;
import com.soundmatt.jfusa.analyze.AnalyzeRules;
import com.soundmatt.jfusa.cyber.CyberRules;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class EngineTest {

    @TempDir Path tmp;

    @Test
    void defaultRegistry_hasBuiltinRules() {
        // Trigger class loading
        LintRules.activate(); AnalyzeRules.activate(); CyberRules.activate();
        List<Rule> rules = Engine.DEFAULT.rules();
        assertFalse(rules.isEmpty());
        assertTrue(rules.stream().anyMatch(r -> r.id().equals("FUSA001")));
        assertTrue(rules.stream().anyMatch(r -> r.id().equals("FUSA002")));
        assertTrue(rules.stream().anyMatch(r -> r.id().startsWith("LINT")));
    }

    @Test
    //fusa:test REQ-ENG001
    void registryRulesAreSortedById() {
        LintRules.activate();
        List<Rule> rules = Engine.DEFAULT.rules();
        for (int i = 1; i < rules.size(); i++) {
            assertTrue(rules.get(i - 1).id().compareTo(rules.get(i).id()) <= 0,
                    "Rules not sorted: " + rules.get(i - 1).id() + " > " + rules.get(i).id());
        }
    }

    @Test
    //fusa:test REQ-ENG008
    void engineRun_onEmptyDir_producesFindings() throws Exception {
        Config cfg = Config.defaultConfig("engine-test");
        Engine.Result result = Engine.DEFAULT.run(tmp, cfg);
        assertNotNull(result);
        assertFalse(result.findings().isEmpty(), "Expected at least FUSA001 finding on empty dir");
    }

    @Test
    //fusa:test REQ-ENG008
    void engineRun_withFusaJson_reducesFindings() throws Exception {
        Config cfg = Config.defaultConfig("engine-test");
        Config.save(tmp, cfg);
        Engine.Result result = Engine.DEFAULT.run(tmp, cfg);
        // FUSA001 should not fire since .fusa.json is present
        result.findings().stream()
                .filter(f -> f.ruleId().equals("FUSA001"))
                .forEach(f -> fail("FUSA001 should not fire when .fusa.json is present: " + f.message()));
    }

    @Test
    //fusa:test REQ-ENG007
    void engineRunFilter_filtersByPrefix() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("filter-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().startsWith("LINT"));
        result.findings().forEach(f ->
                assertTrue(f.ruleId().startsWith("LINT"),
                        "Non-LINT finding in filtered run: " + f.ruleId()));
    }

    @Test
    //fusa:test REQ-ENG003
    void resultHasErrors_reflectsSeverity() throws Exception {
        LintRules.activate();
        Config cfg = Config.defaultConfig("err-test");
        // Minimal engine with a forced-error rule
        Registry reg = new Registry();
        reg.mustRegister(new Rule() {
            public String id() { return "TEST001"; }
            public String description() { return "test"; }
            public List<FuSa.Finding> run(Path r, Config c) {
                return List.of(FuSa.Finding.builder("TEST001", FuSa.Severity.ERROR,
                        "forced error", new FuSa.Location("x.java", 1)).build());
            }
        });
        Engine eng = new Engine(reg);
        Engine.Result result = eng.run(tmp, cfg);
        assertTrue(result.hasErrors());
        assertFalse(result.hasWarnings()); // only error, no warning-only findings
    }

    @Test
    //fusa:test REQ-ENG004
    //fusa:test REQ-ENG005
    void duplicateRegister_throws() {
        Registry reg = new Registry();
        Rule r = new Rule() {
            public String id() { return "DUP001"; }
            public String description() { return "dup"; }
            public List<FuSa.Finding> run(Path root, Config cfg) { return List.of(); }
        };
        reg.mustRegister(r);
        assertThrows(IllegalStateException.class, () -> reg.mustRegister(r));
    }

    @Test
    //fusa:test REQ-ENG002
    void engineRun_isolatesRuleFailures_soOtherRulesStillProduceFindings() throws Exception {
        Config cfg = Config.defaultConfig("isolation-test");
        Registry reg = new Registry();
        reg.mustRegister(new Rule() {
            public String id() { return "BOOM001"; }
            public String description() { return "always throws"; }
            public List<FuSa.Finding> run(Path r, Config c) { throw new RuntimeException("boom"); }
        });
        reg.mustRegister(new Rule() {
            public String id() { return "OK001"; }
            public String description() { return "always succeeds"; }
            public List<FuSa.Finding> run(Path r, Config c) {
                return List.of(FuSa.Finding.builder("OK001", FuSa.Severity.INFO,
                        "fine", new FuSa.Location("x.java", 1)).build());
            }
        });
        Engine eng = new Engine(reg);
        Engine.Result result = eng.run(tmp, cfg);
        assertTrue(result.errors().stream().anyMatch(e -> e.contains("BOOM001")),
                "failing rule must be recorded in errors() rather than propagating");
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("OK001")),
                "a successful rule's findings must still be produced despite another rule's failure");
    }
}
