package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.cyber.CyberRules;
import com.soundmatt.jfusa.engine.Engine;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class CyberRulesTest {

    @TempDir Path tmp;

    @Test
    void cyber001_detectsSqlConcatenation() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Dao.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Dao {
                    String query(String id) {
                        return "SELECT * FROM t WHERE id = " + id;
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER001"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER001")),
                "CYBER001 should detect SQL string concatenation");
    }

    @Test
    void cyber005_detectsHardcodedPassword() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Auth.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Auth {
                    private static final String PASSWORD = "s3cr3t123";
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER005"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER005")),
                "CYBER005 should detect hardcoded PASSWORD constant");
    }

    @Test
    void cyber007_detectsWeakRandom() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Rand.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import java.util.Random;
                public class Rand {
                    int next() { return new Random().nextInt(); }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER007"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER007")),
                "CYBER007 should detect java.util.Random");
    }

    @Test
    void cyber020_detectsMissingSecurityMd() throws Exception {
        CyberRules.activate();
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER020"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER020")),
                "CYBER020 should fire when SECURITY.md is missing");
    }
}
