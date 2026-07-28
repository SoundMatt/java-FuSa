package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.lint.LintRules;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class LintRulesTest {

    @TempDir Path tmp;

    @Test
    //fusa:test REQ-LINT001
    void lint001_detectsReturnNull() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    public String foo() {
                        return null;
                    }
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT001"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("LINT001")),
                "LINT001 should fire on 'return null' without //fusa:unsafe");
    }

    @Test
    //fusa:test REQ-LINT001
    void lint001_allowsReturnNull_withAnnotation() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    public String foo() {
                        return null; //fusa:unsafe intentionally null
                    }
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT001"));
        assertTrue(result.findings().stream().noneMatch(f -> f.ruleId().equals("LINT001")),
                "LINT001 should NOT fire when //fusa:unsafe is present");
    }

    @Test
    //fusa:test REQ-LINT002
    void lint002_detectsSystemExit() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    public void shutdown() {
                        System.exit(1);
                    }
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT002"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("LINT002")));
    }

    @Test
    //fusa:test REQ-LINT005
    void lint005_detectsFloatEquals() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    boolean bad(double x) { return x == 0.5; }
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT005"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("LINT005")));
    }

    @Test
    //fusa:test REQ-LINT007
    void lint007_detectsSysout() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    void bad() { System.out.println("debug"); }
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT007"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("LINT007")));
    }

    @Test
    //fusa:test REQ-LINT003
    void lint003_detectsRawThreadCreation() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    void bad() { new Thread(() -> {}).start(); }
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT003"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("LINT003")));
    }

    @Test
    //fusa:test REQ-LINT004
    void lint004_detectsStaticMutableField() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    static String[] data;
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT004"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("LINT004")));
    }

    @Test
    //fusa:test REQ-LINT006
    void lint006_detectsRecursiveMethodWithoutAnnotation() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    private void loop(int n) {
                        if (n > 0) loop(n - 1);
                    }
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT006"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("LINT006")));
    }

    @Test
    //fusa:test REQ-LINT008
    void lint008_detectsReflectionWithoutAnnotation() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    void bad() throws Exception {
                        Class.forName("java.lang.String");
                    }
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT008"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("LINT008")));
    }

    @Test
    //fusa:test REQ-LINT009
    void lint009_detectsUncheckedCastSuppression() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    @SuppressWarnings("unchecked")
                    void bad() { java.util.List l = new java.util.ArrayList(); }
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT009"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("LINT009")));
    }

    @Test
    //fusa:test REQ-LINT010
    void lint010_detectsDeprecatedApiUsage() throws Exception {
        LintRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    @Deprecated
                    void oldMethod() {}
                }
                """);
        Config cfg = Config.defaultConfig("lint-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("LINT010"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("LINT010")));
    }

    //fusa:test REQ-LINTUTIL001
    @Test
    void sharedScannerUtilities_workDirectly() throws Exception {
        Path src = tmp.resolve("src/main/java/Util.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Util {
                    //fusa:unsafe intentional
                    void foo() {}
                }
                """);
        Config cfg = Config.defaultConfig("lint-util-test");

        List<Path> files = LintRules.javaFiles(tmp, cfg);
        assertTrue(files.stream().anyMatch(p -> p.equals(src)));

        List<String> lines = LintRules.readLines(src);
        assertTrue(lines.get(0).contains("public class Util"));

        FuSa.Location location = LintRules.loc(tmp, src, 2);
        assertEquals("src/main/java/Util.java", location.file());
        assertEquals(2, location.line());

        assertTrue(LintRules.hasAnnotation(lines, 2, "//fusa:unsafe"));
        assertFalse(LintRules.hasAnnotation(lines, 0, "//fusa:unsafe"));
    }

    /**
     * Regression coverage for x-FuSa/java-FuSa#33 / spec v1.15.0 §1.6 rule 4: {@code
     * isTestSourcePath} is the shared exclusion trace's func-coverage denominator and fmea's
     * derivation both now use to keep test fixtures out of a "real project component" inventory.
     */
    //fusa:test REQ-LINTUTIL002
    @Test
    void isTestSourcePath_recognisesConventionalTestDirectoriesOnly() {
        assertTrue(LintRules.isTestSourcePath(tmp, tmp.resolve("src/test/java/com/example/WidgetTest.java")));
        assertTrue(LintRules.isTestSourcePath(tmp, tmp.resolve("tests/Fixture.java")));
        assertFalse(LintRules.isTestSourcePath(tmp, tmp.resolve("src/main/java/com/example/Widget.java")));
        assertFalse(LintRules.isTestSourcePath(tmp, tmp.resolve("src/main/java/com/example/TestUtils.java")),
                "a file/segment merely containing \"test\" as a substring (not an exact path segment) must not match");
    }
}
