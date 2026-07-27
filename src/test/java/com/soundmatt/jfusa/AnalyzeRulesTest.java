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

    //fusa:test REQ-ANA001
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

    //fusa:test REQ-ANA003
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

    //fusa:test REQ-ANA004
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

    //fusa:test REQ-ANA005
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

    //fusa:test REQ-ANA002
    @Test
    void ana002_detectsUnclosedResource() throws Exception {
        AnalyzeRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import java.io.FileInputStream;
                public class Test {
                    void bad() throws Exception {
                        FileInputStream in = new FileInputStream("x.txt");
                        in.read();
                    }
                }
                """);
        Config cfg = Config.defaultConfig("test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("ANA002"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("ANA002")),
                "ANA002 should detect FileInputStream allocated outside try-with-resources");
    }

    //fusa:test REQ-ANA006
    @Test
    void ana006_detectsExceptionSwallowedWithoutCauseChain() throws Exception {
        AnalyzeRules.activate();
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    void bad() {
                        try {
                            risky();
                        }
                        catch (Exception e) {
                            throw new RuntimeException("wrapped failure");
                        }
                    }
                    void risky() throws Exception {}
                }
                """);
        Config cfg = Config.defaultConfig("test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("ANA006"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("ANA006")),
                "ANA006 should detect throw new X(\"msg\") in a catch block without chaining the cause");
    }
}
