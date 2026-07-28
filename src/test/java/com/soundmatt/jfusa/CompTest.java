package com.soundmatt.jfusa;

import com.soundmatt.jfusa.comp.Comp;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class CompTest {

    @TempDir Path tmp;

    //fusa:test REQ-COMP004
    @Test
    void comp_generate_writesReport() throws Exception {
        Path src = tmp.resolve("src/main/java/Test.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Test {
                    public int simple(int x) {
                        return x + 1;
                    }
                }
                """);
        Comp.generate(tmp);
        assertTrue(Files.exists(tmp.resolve(Comp.COMP_JSON)));
    }

    //fusa:test REQ-COMP002
    //fusa:test REQ-COMP004
    @Test
    void comp_generate_withDalThreshold_writesReport() throws Exception {
        Path src = tmp.resolve("src/main/java/Dal.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Dal {
                    public int simple(int x) {
                        return x + 1;
                    }
                }
                """);
        assertEquals(4, Comp.thresholdForDal("DAL-A"));
        assertEquals(20, Comp.thresholdForDal("DAL-D"));
        assertEquals(Comp.DEFAULT_THRESHOLD, Comp.thresholdForDal("not-a-dal"));

        Comp.generate(tmp, Comp.thresholdForDal("DAL-A"), "DAL-A");
        String content = Files.readString(tmp.resolve(Comp.COMP_JSON));
        assertTrue(content.contains("\"dal\""));
        assertTrue(content.contains("DAL-A"));
    }

    //fusa:test REQ-COMP001
    //fusa:test REQ-COMP003
    @Test
    void comp_analyze_detectsLowComplexity() throws Exception {
        Path src = tmp.resolve("src/main/java/Simple.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Simple {
                    public int add(int a, int b) { return a + b; }
                }
                """);
        List<Comp.MethodComplexity> results = Comp.analyze(tmp);
        // Simple method should have complexity 1 (no branches)
        results.stream()
                .filter(r -> r.method().equals("add"))
                .forEach(r -> assertTrue(r.complexity() <= 2));
    }

    /**
     * Regression test for x-FuSa/java-FuSa#35: {@code extractMethodName} must not fall back to
     * "unknown" for the common shapes the old single-token-return-type regex missed — a
     * multi-modifier declaration, a generic/parameterized return type, and a no-arg constructor.
     */
    //fusa:test REQ-COMP006
    @Test
    void extractMethodName_handlesMultiModifierGenericReturnTypeAndConstructor() {
        assertEquals("load", Comp.extractMethodName("public static List<Entry> load(String path) {"));
        assertEquals("activate", Comp.extractMethodName("public static void activate() {"));
        assertEquals("Disposition", Comp.extractMethodName("private Disposition() {}"));
        assertEquals("foo", Comp.extractMethodName("public int foo(int x) {"));
        assertEquals("identity", Comp.extractMethodName("public static <T> T identity(T t) {"));
    }

    /**
     * A same-line method body containing a call expression (e.g. {@code helper()}) must not be
     * mistaken for the declared method's own name — extraction is scoped to the text before the
     * line's first {@code '{'}.
     */
    //fusa:test REQ-COMP006
    @Test
    void extractMethodName_ignoresCallsInsideSameLineBody() {
        assertEquals("run", Comp.extractMethodName("public void run() { helper(); }"));
    }

    /**
     * Real-world regression check: analyzing this tool's own {@code disposition/Disposition.java}
     * and {@code iec62443/Iec62443.java} (the exact files cited in x-FuSa/java-FuSa#35) must no
     * longer yield "unknown" names for their load()/activate()-style declarations.
     */
    //fusa:test REQ-COMP006
    @Test
    void comp_analyze_noLongerReportsUnknownForMultiModifierDeclarations() throws Exception {
        Path src = tmp.resolve("src/main/java/Disposition.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public final class Disposition {
                    private Disposition() {}
                    public static List<Entry> load(String path) {
                        return List.of();
                    }
                    public static void activate() {}
                }
                """);
        List<Comp.MethodComplexity> results = Comp.analyze(tmp);
        assertTrue(results.stream().noneMatch(r -> r.method().equals("unknown")),
                "no method in this fixture should resolve to \"unknown\"");
        assertTrue(results.stream().anyMatch(r -> r.method().equals("load")));
        assertTrue(results.stream().anyMatch(r -> r.method().equals("activate")));
        assertTrue(results.stream().anyMatch(r -> r.method().equals("Disposition")));
    }

    //fusa:test REQ-COMP005
    @Test
    void comp001_rule_firesOnHighComplexity() throws Exception {
        Comp.activate();
        Path src = tmp.resolve("src/main/java/Complex.java");
        Files.createDirectories(src.getParent());
        // Generate a method with many branches (complexity > 10)
        var sb = new StringBuilder("public class Complex {\n    public int high(int x) {\n");
        for (int i = 0; i < 12; i++) sb.append("        if (x == ").append(i).append(") return ").append(i).append(";\n");
        sb.append("        return -1;\n    }\n}");
        Files.writeString(src, sb.toString());
        Config cfg = Config.defaultConfig("comp-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("COMP001"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("COMP001")),
                "COMP001 should fire on method with complexity > 10");
    }
}
