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

    //fusa:test REQ-CYBER001
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
        // Regression (issue #44): standard used to be the CWE weakness id "CWE-89" —
        // §2.4.1 reserves `standard` for the governing standard, never a CWE id.
        assertTrue(result.findings().stream()
                        .filter(f -> f.ruleId().equals("CYBER001"))
                        .noneMatch(f -> f.standard().startsWith("CWE")),
                "Finding.standard must not carry a CWE-<n> value");
    }

    //fusa:test REQ-CYBER005
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

    //fusa:test REQ-CYBER007
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

    //fusa:test REQ-CYBER020
    @Test
    void cyber020_detectsMissingSecurityMd() throws Exception {
        CyberRules.activate();
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER020"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER020")),
                "CYBER020 should fire when SECURITY.md is missing");
    }

    //fusa:test REQ-CYBER002
    @Test
    void cyber002_detectsCommandInjection() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Runner.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Runner {
                    void run(String cmd) throws Exception {
                        Runtime.getRuntime().exec(cmd);
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER002"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER002")),
                "CYBER002 should detect Runtime.getRuntime().exec");
    }

    //fusa:test REQ-CYBER003
    @Test
    void cyber003_detectsXss() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Echo.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Echo {
                    void handle(Object response, Object request) throws Exception {
                        response.getWriter().print(request.getParameter("name"));
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER003"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER003")),
                "CYBER003 should detect unescaped output write");
    }

    //fusa:test REQ-CYBER004
    @Test
    void cyber004_detectsPathTraversal() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Files2.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Files2 {
                    void open(Object request) throws Exception {
                        new File(request.getParameter("path"));
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER004"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER004")),
                "CYBER004 should detect File constructed from user input");
    }

    //fusa:test REQ-CYBER006
    @Test
    void cyber006_detectsHardcodedKey() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Keys.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Keys {
                    private static final String apiKey = "abcdef0123456789";
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER006"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER006")),
                "CYBER006 should detect hardcoded apiKey constant");
    }

    //fusa:test REQ-CYBER008
    @Test
    void cyber008_detectsWeakCipher() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Crypto.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import javax.crypto.Cipher;
                public class Crypto {
                    Cipher get() throws Exception {
                        return Cipher.getInstance("DES");
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER008"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER008")),
                "CYBER008 should detect Cipher.getInstance(\"DES\")");
    }

    //fusa:test REQ-CYBER009
    @Test
    void cyber009_detectsBrokenHash() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Hash.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import java.security.MessageDigest;
                public class Hash {
                    MessageDigest get() throws Exception {
                        return MessageDigest.getInstance("MD5");
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER009"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER009")),
                "CYBER009 should detect MessageDigest.getInstance(\"MD5\")");
    }

    //fusa:test REQ-CYBER010
    @Test
    void cyber010_detectsInsecureCookie() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Cookies.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import javax.servlet.http.Cookie;
                public class Cookies {
                    void set() {
                        Cookie c = new Cookie("session", "abc");
                        c.setPath("/");
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER010"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER010")),
                "CYBER010 should detect Cookie missing Secure/HttpOnly flags");
        // Regression (issue #44): standard used to be "CWE-614" with a redundant clause "614".
        assertTrue(result.findings().stream()
                        .filter(f -> f.ruleId().equals("CYBER010"))
                        .anyMatch(f -> "iso21434".equals(f.standard())),
                "Finding.standard must be the §2.4.1 canonical id iso21434, not CWE-614");
    }

    //fusa:test REQ-CYBER012
    @Test
    void cyber012_detectsInsecureDeserialization() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Deser.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import java.io.ObjectInputStream;
                public class Deser {
                    Object read(ObjectInputStream in) throws Exception {
                        return in.readObject();
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER012"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER012")),
                "CYBER012 should detect ObjectInputStream usage");
    }

    //fusa:test REQ-CYBER013
    @Test
    void cyber013_detectsSsrf() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Fetch.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import java.net.URL;
                public class Fetch {
                    void go(Object request) throws Exception {
                        new URL(request.getParameter("url"));
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER013"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER013")),
                "CYBER013 should detect URL constructed from user input");
    }

    //fusa:test REQ-CYBER014
    @Test
    void cyber014_detectsLogInjection() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Logging.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Logging {
                    void log(Object logger, Object request) throws Exception {
                        logger.info(request.getParameter("name"));
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER014"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER014")),
                "CYBER014 should detect logger.info with unsanitised user input");
    }

    //fusa:test REQ-CYBER015
    @Test
    void cyber015_detectsIntegerOverflow() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Overflow.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Overflow {
                    int compute(long a, long b) {
                        return (int) (a * b);
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER015"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER015")),
                "CYBER015 should detect narrowing (int) cast of a multiplication");
    }

    //fusa:test REQ-CYBER016
    @Test
    void cyber016_detectsInformationExposure() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/ErrHandler.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class ErrHandler {
                    void handle(Exception e) {
                        e.printStackTrace();
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER016"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER016")),
                "CYBER016 should detect printStackTrace()");
    }

    //fusa:test REQ-CYBER018
    @Test
    void cyber018_detectsReDoS() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Regex.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                import java.util.regex.Pattern;
                public class Regex {
                    static final Pattern P = Pattern.compile("(a*)+");
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER018"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER018")),
                "CYBER018 should detect a catastrophic-backtracking regex pattern");
    }

    //fusa:test REQ-CYBER019
    @Test
    void cyber019_detectsResourceExhaustion() throws Exception {
        CyberRules.activate();
        Path src = tmp.resolve("src/main/java/Buf.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Buf {
                    byte[] alloc(int requestSize) {
                        return new byte[requestSize];
                    }
                }
                """);
        Config cfg = Config.defaultConfig("cyber-test");
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("CYBER019"));
        assertTrue(result.findings().stream().anyMatch(f -> f.ruleId().equals("CYBER019")),
                "CYBER019 should detect byte array allocated with a request-derived size");
    }
}
