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
}
