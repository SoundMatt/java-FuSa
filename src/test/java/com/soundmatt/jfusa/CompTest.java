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
