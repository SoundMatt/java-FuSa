package com.soundmatt.jfusa;

import com.soundmatt.jfusa.boundary.Boundary;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.coupling.Coupling;
import com.soundmatt.jfusa.coverage.Coverage;
import com.soundmatt.jfusa.cyber.CyberRules;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.fmea.Fmea;
import com.soundmatt.jfusa.hooks.Hooks;
import com.soundmatt.jfusa.iec62443.Iec62443;
import com.soundmatt.jfusa.impact.Impact;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.misra.Misra;
import com.soundmatt.jfusa.template.Template;
import com.soundmatt.jfusa.verify.Verify;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Gap-coverage tests targeting 0% and low-coverage inner classes.
 */
class GapCoverageTest {

    @TempDir Path tmp;

    // ── FuSa.InvalidConfigException (0%) ─────────────────────────────────────

    @Test
    //fusa:test REQ-ERR002
    void fusaInvalidConfigException_messageContainsPrefix() {
        FuSa.InvalidConfigException ex = new FuSa.InvalidConfigException("bad field");
        assertTrue(ex.getMessage().contains("jfusa: invalid configuration:"),
                "InvalidConfigException message must include the standard prefix");
        assertTrue(ex.getMessage().contains("bad field"));
    }

    @Test
    //fusa:test REQ-ERR002
    void fusaInvalidConfigException_isRuntimeException() {
        FuSa.InvalidConfigException ex = new FuSa.InvalidConfigException("x");
        assertInstanceOf(RuntimeException.class, ex);
    }

    // ── Coupling.CouplingEntry (0%) ───────────────────────────────────────────

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-COUPLING001
    void couplingEntry_recordAccessors() {
        Coupling.CouplingEntry e = new Coupling.CouplingEntry("Foo.java", "Bar.baz", "control", 42);
        assertEquals("Foo.java", e.from());
        assertEquals("Bar.baz", e.to());
        assertEquals("control", e.type());
        assertEquals(42, e.line());
    }

    @Test
    //fusa:test REQ-NF001
    void couplingEntry_dataType() {
        Coupling.CouplingEntry e = new Coupling.CouplingEntry("A.java", "someMethod", "data", 7);
        assertEquals("data", e.type());
    }

    // ── Coverage.CoverageReport (0%) ─────────────────────────────────────────

    @Test
    //fusa:test REQ-COV001
    //fusa:test REQ-COV002
    void coverageReport_recordAccessors() {
        Coverage.CoverageReport r = new Coverage.CoverageReport(85.5, 72.0, 90.0);
        assertEquals(85.5, r.statementPct(), 0.001);
        assertEquals(72.0, r.branchPct(), 0.001);
        assertEquals(90.0, r.methodPct(), 0.001);
    }

    @Test
    //fusa:test REQ-COV001
    //fusa:test REQ-COV002
    void coverageReport_zeroWhenFileAbsent() throws Exception {
        Coverage.CoverageReport r = Coverage.parse(tmp.resolve("does-not-exist.xml"));
        assertEquals(0.0, r.statementPct(), 0.001);
        assertEquals(0.0, r.branchPct(), 0.001);
        assertEquals(0.0, r.methodPct(), 0.001);
    }

    @Test
    //fusa:test REQ-COV001
    //fusa:test REQ-COV002
    void coverageReport_parseJacocoXml() throws Exception {
        Path jacoco = tmp.resolve("jacoco.xml");
        Files.writeString(jacoco, """
                <?xml version="1.0" encoding="UTF-8"?>
                <report name="test">
                  <counter type="INSTRUCTION" missed="10" covered="90"/>
                  <counter type="BRANCH" missed="5" covered="15"/>
                  <counter type="METHOD" missed="2" covered="18"/>
                </report>
                """);
        Coverage.CoverageReport r = Coverage.parse(jacoco);
        assertEquals(90.0, r.statementPct(), 0.001);
        assertEquals(75.0, r.branchPct(), 0.001);
        assertEquals(90.0, r.methodPct(), 0.001);
    }

    // ── Coverage.RuleCoverageGate (29.4%) ─────────────────────────────────────

    @Test
    //fusa:test REQ-COV001
    void ruleCoverageGate_noFindingWhenNoJacocoFile() throws Exception {
        Coverage.activate();
        Config cfg = Config.defaultConfig("cov-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("COV001"));
        assertTrue(result.findings().isEmpty(),
                "COV001 should not fire when jacoco.xml is absent");
    }

    @Test
    //fusa:test REQ-COV001
    //fusa:test REQ-COV002
    void ruleCoverageGate_firesWhenCoverageBelowThreshold() throws Exception {
        Coverage.activate();
        Path jacocoDir = tmp.resolve("target/site/jacoco");
        Files.createDirectories(jacocoDir);
        Files.writeString(jacocoDir.resolve("jacoco.xml"), """
                <?xml version="1.0" encoding="UTF-8"?>
                <report name="test">
                  <counter type="INSTRUCTION" missed="50" covered="50"/>
                  <counter type="BRANCH" missed="5" covered="5"/>
                  <counter type="METHOD" missed="3" covered="7"/>
                </report>
                """);
        Config cfg = Config.defaultConfig("cov-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("COV001"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("COV001")),
                "COV001 should fire when statement coverage is below 80%");
    }

    @Test
    //fusa:test REQ-COV001
    //fusa:test REQ-COV002
    void ruleCoverageGate_noFindingWhenCoverageAboveThreshold() throws Exception {
        Coverage.activate();
        Path jacocoDir = tmp.resolve("target/site/jacoco");
        Files.createDirectories(jacocoDir);
        Files.writeString(jacocoDir.resolve("jacoco.xml"), """
                <?xml version="1.0" encoding="UTF-8"?>
                <report name="test">
                  <counter type="INSTRUCTION" missed="10" covered="90"/>
                  <counter type="BRANCH" missed="5" covered="15"/>
                  <counter type="METHOD" missed="2" covered="18"/>
                </report>
                """);
        Config cfg = Config.defaultConfig("cov-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("COV001"));
        assertTrue(result.findings().stream().noneMatch(f -> f.ruleId().equals("COV001")),
                "COV001 should not fire when statement coverage >= 80%");
    }

    // ── Fmea.FailureMode (0%) ──────────────────────────────────────────────────

    @Test
    //fusa:test REQ-NF001
    void fmeaEntry_recordAccessors() {
        Fmea.FailureMode e = new Fmea.FailureMode(
                "FMEA-001", "MyClass", "doSomething", "MyClass.doSomething", "MyClass.java",
                "Returns incorrect value", "Safety output invalid", "Implementation defect",
                "high", "Low", "Code review", "high", List.of(), List.of());
        assertEquals("FMEA-001", e.id());
        assertEquals("MyClass", e.component());
        assertEquals("doSomething", e.method());
        assertEquals("Returns incorrect value", e.failureMode());
        assertEquals("Safety output invalid", e.effect());
        assertEquals("high", e.severity());
        assertEquals("Low", e.occurrence());
        assertEquals("Code review", e.detection());
        assertEquals("high", e.actionPriority());
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-FMEA001
    void fmea_generate_writesFiles() throws Exception {
        Path srcDir = tmp.resolve("src/main/java");
        Files.createDirectories(srcDir);
        Files.writeString(srcDir.resolve("Safe.java"), """
                public class Safe {
                    public void safeShutdown() {}
                    public void validateInput(String s) {}
                    public void processData() {}
                }
                """);
        Config cfg = Config.defaultConfig("fmea-test");
        Fmea.FmeaReport report = Fmea.build(tmp, cfg);
        Fmea.writeJson(tmp, report, "");
        Fmea.writeCsv(tmp, report.entries());
        assertTrue(Files.exists(tmp.resolve(Fmea.FMEA_JSON)), "fmea.json should be written");
        assertTrue(Files.exists(tmp.resolve(Fmea.FMEA_CSV)),  "fmea.csv should be written");
        String json = Files.readString(tmp.resolve(Fmea.FMEA_JSON));
        assertTrue(json.contains("\"kind\": \"fmea-report\""),
                "JSON should contain kind field");
        String csv = Files.readString(tmp.resolve(Fmea.FMEA_CSV));
        assertTrue(csv.contains("ID,Item"), "CSV must have header");
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-FMEA001
    void fmea_derive_classifiesSeverityFromMethodNames() throws Exception {
        Path srcDir = tmp.resolve("src/main/java");
        Files.createDirectories(srcDir);
        Files.writeString(srcDir.resolve("SafetyClass.java"), """
                public class SafetyClass {
                    public void safeShutdown() {}
                    public void validateInput(String s) {}
                    public void processData() {}
                }
                """);
        Config cfg = Config.defaultConfig("fmea-test");
        List<Fmea.FailureMode> entries = Fmea.derive(tmp, cfg);
        assertFalse(entries.isEmpty(), "derive should produce entries for public methods");
        // safeShutdown -> high, validateInput -> medium, processData -> low
        assertTrue(entries.stream().anyMatch(e -> e.method().equals("safeShutdown") && "high".equals(e.severity())),
                "safeShutdown should be classified as high");
        assertTrue(entries.stream().anyMatch(e -> e.method().equals("validateInput") && "medium".equals(e.severity())),
                "validateInput should be classified as medium");
        assertTrue(entries.stream().anyMatch(e -> e.method().equals("processData") && "low".equals(e.severity())),
                "processData should be classified as low");
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-FMEA001
    void fmea_derive_actionPriorityMapsFromSeverity() throws Exception {
        Path srcDir = tmp.resolve("src/main/java");
        Files.createDirectories(srcDir);
        Files.writeString(srcDir.resolve("RpnTest.java"), """
                public class RpnTest {
                    public void safeHalt() {}
                    public void checkStatus() {}
                    public void buildReport() {}
                }
                """);
        Config cfg = Config.defaultConfig("fmea-test");
        List<Fmea.FailureMode> entries = Fmea.derive(tmp, cfg);
        entries.stream().filter(e -> "high".equals(e.severity()))
               .forEach(e -> assertEquals("high", e.actionPriority(), "high severity should map to high priority"));
        entries.stream().filter(e -> "medium".equals(e.severity()))
               .forEach(e -> assertEquals("medium", e.actionPriority(), "medium severity should map to medium priority"));
        entries.stream().filter(e -> "low".equals(e.severity()))
               .forEach(e -> assertEquals("low", e.actionPriority(), "low severity should map to low priority"));
    }

    // ── Json.JsonParseException (0%) ──────────────────────────────────────────

    @Test
    //fusa:test REQ-NF001
    void jsonParseException_hasMessage() {
        Json.JsonParseException ex = new Json.JsonParseException("unexpected token at pos 5");
        assertEquals("unexpected token at pos 5", ex.getMessage());
        assertInstanceOf(RuntimeException.class, ex);
    }

    @Test
    //fusa:test REQ-NF001
    void jsonParseException_thrownOnBadInput() {
        assertThrows(Json.JsonParseException.class, () -> Json.parseObject("not-json"));
        assertThrows(Json.JsonParseException.class, () -> Json.parseObject("[1,2,3]"),
                "parseObject should throw when root is not an object");
        assertThrows(Json.JsonParseException.class, () -> Json.parseObject(null));
    }

    @Test
    //fusa:test REQ-NF001
    void jsonParseException_thrownOnUnterminatedString() {
        assertThrows(Json.JsonParseException.class, () -> Json.parse("{\"key\":\"unterminated"));
    }

    // ── Verify.Evidence (0%) ─────────────────────────────────────────────────

    @Test
    //fusa:test REQ-VERIFY001
    void verifyEvidence_recordAccessors() {
        Verify.Evidence ev = new Verify.Evidence(
                "my-project", "2026-07-27T00:00:00Z", "mvn test", 0, "all tests passed");
        assertEquals("my-project", ev.project());
        assertEquals("2026-07-27T00:00:00Z", ev.timestamp());
        assertEquals("mvn test", ev.testCommand());
        assertEquals(0, ev.exitCode());
        assertEquals("all tests passed", ev.notes());
    }

    @Test
    //fusa:test REQ-VERIFY001
    void verifyEvidence_nonZeroExitCode() {
        Verify.Evidence ev = new Verify.Evidence("p", "t", "mvn test", 1, "failed");
        assertEquals(1, ev.exitCode());
    }

    // ── Template (28.2%) ─────────────────────────────────────────────────────

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-TEMPLATE001
    void template_safetyPlan_writesFile() throws Exception {
        Template.generate(tmp, "safety-plan", "MyProject");
        Path out = tmp.resolve("docs/MyProject-safety-plan.md");
        assertTrue(Files.exists(out), "safety plan file should be created");
        String content = Files.readString(out);
        assertTrue(content.contains("# Safety Plan: MyProject"));
        assertTrue(content.contains("ISO 26262"));
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-TEMPLATE001
    void template_testEvidence_writesFile() throws Exception {
        Template.generate(tmp, "test-evidence", "MyProject");
        Path out = tmp.resolve("docs/MyProject-test-evidence.md");
        assertTrue(Files.exists(out), "test evidence file should be created");
        String content = Files.readString(out);
        assertTrue(content.contains("# Test Evidence Report: MyProject"));
        assertTrue(content.contains("DO-178C"));
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-TEMPLATE001
    void template_hara_writesFile() throws Exception {
        Template.generate(tmp, "hara", "MyProject");
        Path out = tmp.resolve("docs/MyProject-hara.md");
        assertTrue(Files.exists(out), "hara file should be created");
        String content = Files.readString(out);
        assertTrue(content.contains("Hazard Analysis and Risk Assessment"));
        assertTrue(content.contains("ISO 26262-3"));
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-TEMPLATE001
    void template_qualificationPlan_writesFile() throws Exception {
        Template.generate(tmp, "qualification-plan", "MyProject");
        Path out = tmp.resolve("docs/MyProject-qualification-plan.md");
        assertTrue(Files.exists(out), "qualification plan file should be created");
        String content = Files.readString(out);
        assertTrue(content.contains("Tool Qualification Plan"));
        assertTrue(content.contains("DO-178C"));
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-TEMPLATE001
    void template_safetyPlan_sanitisesSpecialChars() throws Exception {
        Template.generate(tmp, "safety-plan", "My Project/v2");
        // Should not throw and should write a file with sanitized name
        // Special chars become underscores
        assertTrue(Files.list(tmp.resolve("docs")).anyMatch(p -> p.getFileName().toString().endsWith("-safety-plan.md")));
    }

    // ── CyberRules.RuleCWE352CSRF (34.8%) ─────────────────────────────────────

    @Test
    //fusa:test REQ-CYBER017
    void cyber017_detectsCsrfInServletWithoutToken() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/MyServlet.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class MyServlet {
                    public void doPost(HttpServletRequest req, HttpServletResponse resp) {
                        String name = req.getParameter("name");
                        // no token validation performed here
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER017"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER017")),
                "CYBER017 should fire for Servlet with doPost and no CSRF token");
    }

    @Test
    //fusa:test REQ-CYBER017
    void cyber017_noFindingWhenCsrfTokenPresent() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/SafeServlet.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class SafeServlet {
                    public void doPost(HttpServletRequest req, HttpServletResponse resp) {
                        String csrfToken = req.getParameter("_token");
                        validateCsrf(csrfToken);
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER017"));
        assertTrue(result.findings().stream().noneMatch(f -> f.ruleId().equals("CYBER017")),
                "CYBER017 should not fire when CSRF token is present");
    }

    @Test
    //fusa:test REQ-CYBER017
    void cyber017_noFindingForNonServletClass() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/MyService.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class MyService {
                    public void doPost() {
                        // not a Servlet or Controller, should be ignored
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER017"));
        assertTrue(result.findings().stream().noneMatch(f -> f.ruleId().equals("CYBER017")),
                "CYBER017 should only target Servlet/Controller classes");
    }

    @Test
    //fusa:test REQ-CYBER017
    void cyber017_detectsPostMappingWithoutCsrf() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/MyController.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                @RestController
                public class MyController {
                    @PostMapping("/submit")
                    public String submit(String data) {
                        return process(data);
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER017"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER017")),
                "CYBER017 should fire for @PostMapping without CSRF check");
    }

    // ── CyberRules.RuleCWE611XXE (44.0%) ─────────────────────────────────────

    @Test
    //fusa:test REQ-CYBER011
    void cyber011_detectsDocumentBuilderFactoryWithoutXxeProtection() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/XmlParser.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import javax.xml.parsers.DocumentBuilderFactory;
                public class XmlParser {
                    void parse(String xml) throws Exception {
                        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                        // no XXE protection configured
                        var builder = factory.newDocumentBuilder();
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER011"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER011")),
                "CYBER011 should fire when XML factory has no XXE protection");
    }

    @Test
    //fusa:test REQ-CYBER011
    void cyber011_noFindingWhenXxeProtectionPresent() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/SafeXmlParser.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import javax.xml.parsers.DocumentBuilderFactory;
                public class SafeXmlParser {
                    void parse(String xml) throws Exception {
                        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
                        factory.setExpandEntityReferences(false);
                        var builder = factory.newDocumentBuilder();
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER011"));
        assertTrue(result.findings().stream().noneMatch(f -> f.ruleId().equals("CYBER011")),
                "CYBER011 should not fire when XXE protection is configured");
    }

    @Test
    //fusa:test REQ-CYBER011
    void cyber011_noFindingWhenAnnotatedUnsafe() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/LegacyXmlParser.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import javax.xml.parsers.DocumentBuilderFactory;
                public class LegacyXmlParser {
                    void parse(String xml) throws Exception {
                        //fusa:unsafe
                        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER011"));
        assertTrue(result.findings().stream().noneMatch(f -> f.ruleId().equals("CYBER011")),
                "CYBER011 should not fire when annotated with //fusa:unsafe");
    }

    // ── Boundary (41.2%) ─────────────────────────────────────────────────────

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-BOUNDARY001
    void boundary_buildDependencyGraph_emptyWhenNoSrcDir() throws Exception {
        Config cfg = Config.defaultConfig("boundary-test");
        Map<String, Set<String>> graph = Boundary.buildDependencyGraph(tmp, cfg);
        assertTrue(graph.isEmpty(), "graph should be empty when no src/main/java exists");
    }

    @Test
    //fusa:test REQ-NF001
    void boundary_buildDependencyGraph_detectsImports() throws Exception {
        Path srcDir = tmp.resolve("src/main/java/com/example");
        Files.createDirectories(srcDir);
        Files.writeString(srcDir.resolve("MyClass.java"), """
                package com.example;
                import com.example.other.OtherClass;
                import com.example.util.Helper;
                public class MyClass {}
                """);
        Config cfg = Config.defaultConfig("boundary-test");
        Map<String, Set<String>> graph = Boundary.buildDependencyGraph(tmp, cfg);
        assertTrue(graph.containsKey("com.example"),
                "graph should contain com.example package");
        Set<String> deps = graph.get("com.example");
        assertTrue(deps.contains("com.example.other"), "should detect com.example.other dependency");
        assertTrue(deps.contains("com.example.util"), "should detect com.example.util dependency");
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-BOUNDARY001
    void boundary_generate_writesBothFiles() throws Exception {
        Path srcDir = tmp.resolve("src/main/java/com/test");
        Files.createDirectories(srcDir);
        Files.writeString(srcDir.resolve("Foo.java"), """
                package com.test;
                import com.test.bar.Bar;
                public class Foo {}
                """);
        Config cfg = Config.defaultConfig("boundary-test");
        Boundary.generate(tmp, cfg);
        assertTrue(Files.exists(tmp.resolve(Boundary.BOUNDARY_MERMAID)),
                "boundary.mermaid should be written");
        assertTrue(Files.exists(tmp.resolve(Boundary.BOUNDARY_DOT)),
                "boundary.dot should be written");
        String mermaid = Files.readString(tmp.resolve(Boundary.BOUNDARY_MERMAID));
        assertTrue(mermaid.startsWith("graph TD"), "mermaid must start with graph TD");
        String dot = Files.readString(tmp.resolve(Boundary.BOUNDARY_DOT));
        assertTrue(dot.contains("digraph boundary"), "dot must contain digraph declaration");
    }

    @Test
    //fusa:test REQ-NF001
    void boundary_ignoresJavaStdlibImports() throws Exception {
        Path srcDir = tmp.resolve("src/main/java/com/test");
        Files.createDirectories(srcDir);
        Files.writeString(srcDir.resolve("Bar.java"), """
                package com.test;
                import java.util.List;
                import javax.servlet.http.HttpServlet;
                import com.test.sub.Sub;
                public class Bar {}
                """);
        Config cfg = Config.defaultConfig("boundary-test");
        Map<String, Set<String>> graph = Boundary.buildDependencyGraph(tmp, cfg);
        Set<String> deps = graph.getOrDefault("com.test", Set.of());
        assertFalse(deps.contains("java.util"), "java.* imports should be ignored");
        assertFalse(deps.contains("javax.servlet.http"), "javax.* imports should be ignored");
        assertTrue(deps.contains("com.test.sub"), "internal imports should be included");
    }

    // ── Hooks (44.4%) ─────────────────────────────────────────────────────────

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-HOOKS001
    void hooks_install_requiresGitRepo() throws Exception {
        // tmp has no .git directory; should print error and return without throwing
        Hooks.install(tmp);
        // Should not throw; just print a warning. No hook file should be created.
        assertFalse(Files.exists(tmp.resolve(".git/hooks/pre-commit")));
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-HOOKS001
    void hooks_remove_noopWhenNoHookPresent() throws Exception {
        // No .git/hooks/pre-commit — should print message without error
        Hooks.remove(tmp);
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-HOOKS001
    void hooks_install_writesHookScript() throws Exception {
        Path hooksDir = tmp.resolve(".git/hooks");
        Files.createDirectories(hooksDir);
        Hooks.install(tmp);
        Path hookFile = hooksDir.resolve("pre-commit");
        assertTrue(Files.exists(hookFile), "pre-commit hook should be written");
        String content = Files.readString(hookFile);
        assertTrue(content.contains("jfusa pre-commit hook"),
                "hook must contain jfusa identifier");
        assertTrue(content.contains("jfusa check --strict"),
                "hook must invoke jfusa check --strict");
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-HOOKS001
    void hooks_remove_deletesJfusaManagedHook() throws Exception {
        Path hooksDir = tmp.resolve(".git/hooks");
        Files.createDirectories(hooksDir);
        Hooks.install(tmp);
        Path hookFile = hooksDir.resolve("pre-commit");
        assertTrue(Files.exists(hookFile));
        Hooks.remove(tmp);
        assertFalse(Files.exists(hookFile), "jfusa-managed hook should be deleted by remove");
    }

    @Test
    //fusa:test REQ-NF001
    void hooks_remove_doesNotDeleteNonJfusaHook() throws Exception {
        Path hooksDir = tmp.resolve(".git/hooks");
        Files.createDirectories(hooksDir);
        Path hookFile = hooksDir.resolve("pre-commit");
        Files.writeString(hookFile, "#!/bin/sh\necho 'custom hook'\n");
        Hooks.remove(tmp);
        assertTrue(Files.exists(hookFile), "non-jfusa hook should not be deleted");
    }

    // ── Coupling.analyze (integration) ───────────────────────────────────────

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-COUPLING001
    void coupling_analyze_detectsMethodCalls() throws Exception {
        Path srcDir = tmp.resolve("src/main/java");
        Files.createDirectories(srcDir);
        Files.writeString(srcDir.resolve("Caller.java"), """
                public class Caller {
                    void go(Foo foo) {
                        foo.process();
                        foo.validate();
                    }
                }
                """);
        List<Coupling.CouplingEntry> entries = Coupling.analyze(tmp);
        assertFalse(entries.isEmpty(), "analyze should detect method calls");
        assertTrue(entries.stream().anyMatch(e -> "control".equals(e.type())),
                "method calls should be typed as control coupling");
    }

    @Test
    //fusa:test REQ-NF001
    //fusa:test REQ-COUPLING001
    void coupling_analyze_emptyWhenNoSrcDir() throws Exception {
        List<Coupling.CouplingEntry> entries = Coupling.analyze(tmp);
        assertTrue(entries.isEmpty(), "analyze should return empty list when no src/main/java");
    }

    // ── Iec62443.RuleIncidentResponsePresent ─────────────────────────────────

    //fusa:test REQ-IEC62443002
    @Test
    void iec62443001_firesWhenNoIncidentResponse_silentWhenPresent() throws Exception {
        Iec62443.activate();
        Config cfg = Config.defaultConfig("iec62443-rule-test");
        Engine.Result before = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("IEC62443-001"));
        assertTrue(before.findings().stream().anyMatch(f -> f.ruleId().equals("IEC62443-001")));

        Files.writeString(tmp.resolve("INCIDENT-RESPONSE.md"), "# Incident Response Plan");
        Engine.Result after = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("IEC62443-001"));
        assertTrue(after.findings().stream().noneMatch(f -> f.ruleId().equals("IEC62443-001")));
    }

    // ── Impact.analyze/generate ───────────────────────────────────────────────

    //fusa:test REQ-IMPACT001
    @Test
    void impact_analyze_detectsAffectedRequirementsAndTests() throws Exception {
        Files.writeString(tmp.resolve(".fusa-reqs.json"), """
                {"schema":"x-fusa-reqs-1.0","requirements":[
                  {"id":"REQ-FOO001","title":"t","status":"implemented","file":"foo/Foo.java"}
                ]}
                """);
        Path testDir = tmp.resolve("src/test/java/foo");
        Files.createDirectories(testDir);
        Files.writeString(testDir.resolve("FooTest.java"), "class FooTest {}");

        List<String> changed = List.of("src/main/java/foo/Foo.java");
        Impact.ImpactResult result = Impact.analyze(tmp, changed);
        assertTrue(result.affectedReqs().contains("REQ-FOO001"));
        assertTrue(result.affectedTests().stream().anyMatch(t -> t.endsWith("FooTest.java")));
        assertFalse(result.summary().isEmpty());
    }

    //fusa:test REQ-IMPACT001
    @Test
    void impact_generate_writesReport() throws Exception {
        Impact.generate(tmp, List.of("src/main/java/foo/Foo.java"));
        assertTrue(Files.exists(tmp.resolve(Impact.IMPACT_JSON)));
        String content = Files.readString(tmp.resolve(Impact.IMPACT_JSON));
        assertTrue(content.contains("\"impact-report\""));
    }

    // ── Misra.RuleMisra ───────────────────────────────────────────────────────

    //fusa:test REQ-MISRA002
    @Test
    void misra001_firesOnDetectedViolation() throws Exception {
        Misra.activate();
        Path src = tmp.resolve("src/main/java/Bad.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Bad {
                    void f() {
                        System.exit(1);
                    }
                }
                """);
        Config cfg = Config.defaultConfig("misra-rule-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("MISRA001"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("MISRA001")),
                "MISRA001 should fire on a detected MISRA violation");
        // Regression (issue #44): standard used to be the display string "MISRA Java 2023".
        assertTrue(result.findings().stream()
                        .filter(f -> f.ruleId().equals("MISRA001"))
                        .allMatch(f -> "misra-java".equals(f.standard())),
                "Finding.standard must be a canonical lowercase id, not a display string");
    }
}
