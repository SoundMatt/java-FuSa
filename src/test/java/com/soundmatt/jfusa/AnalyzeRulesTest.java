package com.soundmatt.jfusa;

import com.soundmatt.jfusa.analyze.AnalyzeRules;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class AnalyzeRulesTest {

    @TempDir Path tmp;

    @Test
    void ana001_detectsChainedMethodCall() throws Exception {
        AnalyzeRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    String bad(Object o) {
                        return o.toString().toLowerCase();
                    }
                }
                """);
        Config cfg = Config.defaultConfig("test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("ANA001"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("ANA001")),
                "ANA001 should detect chained method call without null check");
    }

    @Test
    void ana003_detectsSynchronizedOnNonFinalField() throws Exception {
        AnalyzeRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    private Object lock = new Object();
                    void bad() {
                        synchronized (lock) { }
                    }
                }
                """);
        Config cfg = Config.defaultConfig("test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("ANA003"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("ANA003")),
                "ANA003 should detect synchronized on non-final field");
    }

    @Test
    void ana004_detectsInterruptedExceptionWithoutReinterrupt() throws Exception {
        AnalyzeRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    void bad() {
                        try { Thread.sleep(100); }
                        catch (InterruptedException e) { System.out.println("ignored"); }
                    }
                }
                """);
        Config cfg = Config.defaultConfig("test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("ANA004"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("ANA004")));
    }

    @Test
    void ana005_detectsEmptyCatch() throws Exception {
        AnalyzeRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    void bad() {
                        try { risky(); }
                        catch (Exception e) {}
                    }
                }
                """);
        Config cfg = Config.defaultConfig("test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("ANA005"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("ANA005")));
    }
}
