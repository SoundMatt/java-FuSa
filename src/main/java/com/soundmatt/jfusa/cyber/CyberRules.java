package com.soundmatt.jfusa.cyber;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.lint.LintRules;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Cybersecurity static analysis — 20 CWE-mapped rules (ISO 21434, CERT Java, OWASP).
 * Registered with the default engine registry at class-load time.
 */
public final class CyberRules {

    static {
        Engine.DEFAULT.mustRegister(new RuleCWE89SQLInjection());
        Engine.DEFAULT.mustRegister(new RuleCWE78CmdInjection());
        Engine.DEFAULT.mustRegister(new RuleCWE79XSS());
        Engine.DEFAULT.mustRegister(new RuleCWE22PathTraversal());
        Engine.DEFAULT.mustRegister(new RuleCWE259HardcodedPassword());
        Engine.DEFAULT.mustRegister(new RuleCWE321HardcodedKey());
        Engine.DEFAULT.mustRegister(new RuleCWE330WeakRandom());
        Engine.DEFAULT.mustRegister(new RuleCWE326WeakCrypto());
        Engine.DEFAULT.mustRegister(new RuleCWE327BrokenHashAlgo());
        Engine.DEFAULT.mustRegister(new RuleCWE614InsecureCookie());
        Engine.DEFAULT.mustRegister(new RuleCWE611XXE());
        Engine.DEFAULT.mustRegister(new RuleCWE502Deserialization());
        Engine.DEFAULT.mustRegister(new RuleCWE918SSRF());
        Engine.DEFAULT.mustRegister(new RuleCWE117LogInjection());
        Engine.DEFAULT.mustRegister(new RuleCWE190IntegerOverflow());
        Engine.DEFAULT.mustRegister(new RuleCWE209InformationExposure());
        Engine.DEFAULT.mustRegister(new RuleCWE352CSRF());
        Engine.DEFAULT.mustRegister(new RuleCWE400ReDoS());
        Engine.DEFAULT.mustRegister(new RuleCWE770ResourceExhaustion());
        Engine.DEFAULT.mustRegister(new RuleSECURITYMDPresent());
    }

    private CyberRules() {}
    public static void activate() {}

    // ── CYBER001: SQL Injection (CWE-89) ─────────────────────────────────────

    static final class RuleCWE89SQLInjection implements Rule {
        private static final Pattern SQL_CONCAT = Pattern.compile(
                "(?:(?:executeQuery|executeUpdate|prepareStatement)\\s*\\(.*\\+)" +
                "|(?:\"\\s*(?:SELECT|INSERT|UPDATE|DELETE|UNION|ALTER|DROP)\\b[^\"]*\"\\s*\\+)");

        public String id() { return "CYBER001"; }
        public String description() { return "SQL injection risk: string concatenation in SQL query (CWE-89)."; }

        //fusa:req REQ-CYBER001
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER001", Severity.ERROR, SQL_CONCAT,
                    "SQL query built via string concatenation — CWE-89 injection risk",
                    "use PreparedStatement with parameterised queries", "CWE-89", "ISO 21434");
        }
    }

    // ── CYBER002: Command Injection (CWE-78) ──────────────────────────────────

    static final class RuleCWE78CmdInjection implements Rule {
        private static final Pattern CMD_INJECT = Pattern.compile(
                "Runtime\\.getRuntime\\(\\)\\.exec|new\\s+ProcessBuilder");

        public String id() { return "CYBER002"; }
        public String description() { return "Command injection risk: process execution with user-controlled data (CWE-78)."; }

        //fusa:req REQ-CYBER002
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER002", Severity.ERROR, CMD_INJECT,
                    "process execution — validate all inputs before passing to Runtime/ProcessBuilder (CWE-78)",
                    "use an allowlist of permitted commands; never pass user input directly",
                    "CWE-78", "ISO 21434");
        }
    }

    // ── CYBER003: XSS (CWE-79) ───────────────────────────────────────────────

    static final class RuleCWE79XSS implements Rule {
        private static final Pattern XSS = Pattern.compile(
                "response\\.getWriter\\(\\)\\.(?:print|write)|out\\.print.*request\\.getParameter");

        public String id() { return "CYBER003"; }
        public String description() { return "Cross-site scripting risk: unescaped output (CWE-79)."; }

        //fusa:req REQ-CYBER003
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER003", Severity.ERROR, XSS,
                    "potential XSS: user input written to response without escaping (CWE-79)",
                    "HTML-escape all untrusted data before rendering; use a templating engine",
                    "CWE-79", "OWASP A03");
        }
    }

    // ── CYBER004: Path Traversal (CWE-22) ────────────────────────────────────

    static final class RuleCWE22PathTraversal implements Rule {
        private static final Pattern PATH_TRAV = Pattern.compile(
                "new\\s+File\\s*\\(.*getParameter|Paths\\.get\\s*\\(.*getParameter");

        public String id() { return "CYBER004"; }
        public String description() { return "Path traversal risk: file path constructed from user input (CWE-22)."; }

        //fusa:req REQ-CYBER004
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER004", Severity.ERROR, PATH_TRAV,
                    "file path from user input — CWE-22 path traversal risk",
                    "validate and canonicalize paths; deny '../' sequences; use an allowlist",
                    "CWE-22", "OWASP A01");
        }
    }

    // ── CYBER005: Hardcoded password (CWE-259) ────────────────────────────────

    static final class RuleCWE259HardcodedPassword implements Rule {
        private static final Pattern HARDCODED_PW = Pattern.compile(
                "(?i)(?:password|passwd|pwd)\\s*=\\s*\"[^\"]{4,}\"");

        public String id() { return "CYBER005"; }
        public String description() { return "Hardcoded password detected (CWE-259)."; }

        //fusa:req REQ-CYBER005
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER005", Severity.ERROR, HARDCODED_PW,
                    "hardcoded credential — CWE-259 password stored in source code",
                    "use environment variables, a secrets manager, or a credential vault",
                    "CWE-259", "OWASP A07");
        }
    }

    // ── CYBER006: Hardcoded key (CWE-321) ────────────────────────────────────

    static final class RuleCWE321HardcodedKey implements Rule {
        private static final Pattern HARDCODED_KEY = Pattern.compile(
                "(?i)(?:secretkey|apikey|api_key|secret)\\s*=\\s*\"[^\"]{8,}\"");

        public String id() { return "CYBER006"; }
        public String description() { return "Hardcoded cryptographic key (CWE-321)."; }

        //fusa:req REQ-CYBER006
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER006", Severity.ERROR, HARDCODED_KEY,
                    "hardcoded key or secret — CWE-321",
                    "load secrets from environment or a key management service",
                    "CWE-321", "ISO 21434");
        }
    }

    // ── CYBER007: Weak random (CWE-330) ──────────────────────────────────────

    static final class RuleCWE330WeakRandom implements Rule {
        private static final Pattern WEAK_RAND = Pattern.compile("new\\s+Random\\s*\\(\\)|Math\\.random\\s*\\(\\)");

        public String id() { return "CYBER007"; }
        public String description() { return "Weak PRNG used for security-sensitive operation (CWE-330)."; }

        //fusa:req REQ-CYBER007
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER007", Severity.WARNING, WEAK_RAND,
                    "java.util.Random / Math.random() are not cryptographically secure (CWE-330)",
                    "use java.security.SecureRandom for all security-sensitive random values",
                    "CWE-330", "CERT Java MSC63-J");
        }
    }

    // ── CYBER008: Weak cipher (CWE-326) ──────────────────────────────────────

    static final class RuleCWE326WeakCrypto implements Rule {
        private static final Pattern WEAK_CIPHER = Pattern.compile(
                "Cipher\\.getInstance\\s*\\(\\s*\"(?:DES|3DES|RC2|RC4|Blowfish|AES/ECB)");

        public String id() { return "CYBER008"; }
        public String description() { return "Weak or obsolete cipher mode (CWE-326)."; }

        //fusa:req REQ-CYBER008
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER008", Severity.ERROR, WEAK_CIPHER,
                    "weak or deprecated cipher — CWE-326 insufficient key strength",
                    "use AES/GCM/NoPadding (256-bit) or AES/CBC/PKCS5Padding with IV",
                    "CWE-326", "CERT Java MSC61-J");
        }
    }

    // ── CYBER009: Broken hash algorithm (CWE-327) ────────────────────────────

    static final class RuleCWE327BrokenHashAlgo implements Rule {
        private static final Pattern BROKEN_HASH = Pattern.compile(
                "MessageDigest\\.getInstance\\s*\\(\\s*\"(?:MD5|SHA-1|SHA1)\"");

        public String id() { return "CYBER009"; }
        public String description() { return "Broken hash algorithm (CWE-327) — MD5 or SHA-1 used."; }

        //fusa:req REQ-CYBER009
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER009", Severity.WARNING, BROKEN_HASH,
                    "MD5/SHA-1 are cryptographically broken — CWE-327",
                    "use SHA-256, SHA-384, or SHA-512 via MessageDigest.getInstance(\"SHA-256\")",
                    "CWE-327", "CERT Java MSC61-J");
        }
    }

    // ── CYBER010: Insecure cookie (CWE-614) ──────────────────────────────────

    static final class RuleCWE614InsecureCookie implements Rule {
        private static final Pattern COOKIE = Pattern.compile("new\\s+Cookie\\s*\\(");

        public String id() { return "CYBER010"; }
        public String description() { return "Cookie created without secure/httpOnly flags (CWE-614)."; }

        //fusa:req REQ-CYBER010
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : LintRules.javaFiles(root, cfg)) {
                List<String> lines = LintRules.readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    if (COOKIE.matcher(lines.get(i)).find()) {
                        // Look for setSecure/setHttpOnly in next 5 lines
                        boolean secure = false, httpOnly = false;
                        for (int j = i; j < Math.min(i + 6, lines.size()); j++) {
                            if (lines.get(j).contains("setSecure(true)")) secure = true;
                            if (lines.get(j).contains("setHttpOnly(true)")) httpOnly = true;
                        }
                        if (!secure || !httpOnly) {
                            out.add(Finding.builder("CYBER010", Severity.WARNING,
                                    "Cookie missing " + (!secure ? "Secure " : "") + (!httpOnly ? "HttpOnly " : "") + "flag (CWE-614)",
                                    LintRules.loc(root, f, i + 1))
                                    .category(FuSa.Category.security)
                                    .standard("CWE-614").clause("614")
                                    .remediation("call cookie.setSecure(true) and cookie.setHttpOnly(true)")
                                    .build());
                        }
                    }
                }
            }
            return out;
        }
    }

    // ── CYBER011: XXE (CWE-611) ──────────────────────────────────────────────

    static final class RuleCWE611XXE implements Rule {
        private static final Pattern XML_FACTORY = Pattern.compile(
                "(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\\.newInstance\\s*\\(\\)");

        public String id() { return "CYBER011"; }
        public String description() { return "XML parser without XXE protection (CWE-611)."; }

        //fusa:req REQ-CYBER011
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : LintRules.javaFiles(root, cfg)) {
                List<String> lines = LintRules.readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    if (XML_FACTORY.matcher(lines.get(i)).find()) {
                        boolean hasXXEProtection = false;
                        for (int j = i; j < Math.min(i + 10, lines.size()); j++) {
                            if (lines.get(j).contains("FEATURE_SECURE_PROCESSING") ||
                                lines.get(j).contains("setExpandEntityReferences(false)") ||
                                lines.get(j).contains("DISALLOW_DOCTYPE_DECL")) {
                                hasXXEProtection = true;
                                break;
                            }
                        }
                        if (!hasXXEProtection && !LintRules.hasAnnotation(lines, i, "//fusa:unsafe")) {
                            out.add(Finding.builder("CYBER011", Severity.ERROR,
                                    "XML parser without XXE protection — CWE-611",
                                    LintRules.loc(root, f, i + 1))
                                    .category(FuSa.Category.security)
                                    .standard("CWE-611").clause("611")
                                    .remediation("disable external entities: factory.setFeature(FEATURE_SECURE_PROCESSING, true)")
                                    .build());
                        }
                    }
                }
            }
            return out;
        }
    }

    // ── CYBER012: Insecure deserialization (CWE-502) ──────────────────────────

    static final class RuleCWE502Deserialization implements Rule {
        private static final Pattern DESER = Pattern.compile("ObjectInputStream|readObject\\s*\\(\\)");

        public String id() { return "CYBER012"; }
        public String description() { return "Insecure deserialization via ObjectInputStream (CWE-502)."; }

        //fusa:req REQ-CYBER012
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER012", Severity.ERROR, DESER,
                    "Java deserialization via ObjectInputStream — CWE-502 remote code execution risk",
                    "use safe data formats (JSON, Protobuf); implement a deserialization filter (JEP 290)",
                    "CWE-502", "OWASP A08");
        }
    }

    // ── CYBER013: SSRF (CWE-918) ─────────────────────────────────────────────

    static final class RuleCWE918SSRF implements Rule {
        private static final Pattern SSRF = Pattern.compile(
                "new\\s+URL\\s*\\(.*getParameter|HttpURLConnection.*getParameter");

        public String id() { return "CYBER013"; }
        public String description() { return "Server-side request forgery risk (CWE-918)."; }

        //fusa:req REQ-CYBER013
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER013", Severity.WARNING, SSRF,
                    "URL from user input — CWE-918 SSRF risk",
                    "validate URLs against an allowlist of permitted hosts",
                    "CWE-918", "OWASP A10");
        }
    }

    // ── CYBER014: Log injection (CWE-117) ────────────────────────────────────

    static final class RuleCWE117LogInjection implements Rule {
        private static final Pattern LOG_INJ = Pattern.compile(
                "(?:log|LOG|logger|LOGGER)\\.(?:info|warn|error|debug)\\s*\\(.*getParameter");

        public String id() { return "CYBER014"; }
        public String description() { return "Log injection: user input logged without sanitisation (CWE-117)."; }

        //fusa:req REQ-CYBER014
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER014", Severity.WARNING, LOG_INJ,
                    "user input logged without stripping newlines — CWE-117 log injection",
                    "sanitise input before logging: strip \\n and \\r",
                    "CWE-117", "CERT Java IDS03-J");
        }
    }

    // ── CYBER015: Integer overflow (CWE-190) ──────────────────────────────────

    static final class RuleCWE190IntegerOverflow implements Rule {
        private static final Pattern INT_OVERFLOW = Pattern.compile(
                "\\(int\\)\\s*\\(.*\\*|\\(int\\)\\s*(?:Long|Integer)\\.MAX");

        public String id() { return "CYBER015"; }
        public String description() { return "Potential integer overflow from unsafe narrowing cast (CWE-190)."; }

        //fusa:req REQ-CYBER015
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER015", Severity.WARNING, INT_OVERFLOW,
                    "narrowing integer cast may overflow — CWE-190",
                    "use Math.toIntExact() for checked narrowing; add overflow guard",
                    "CWE-190", "CERT Java NUM00-J");
        }
    }

    // ── CYBER016: Information exposure in exceptions (CWE-209) ───────────────

    static final class RuleCWE209InformationExposure implements Rule {
        private static final Pattern EXCEPTION_MSG = Pattern.compile(
                "(?:response|out)\\.(?:print|write).*e\\.getMessage|printStackTrace\\s*\\(\\)");

        public String id() { return "CYBER016"; }
        public String description() { return "Exception details leaked to client (CWE-209)."; }

        //fusa:req REQ-CYBER016
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER016", Severity.WARNING, EXCEPTION_MSG,
                    "exception message or stack trace returned to client — CWE-209 information exposure",
                    "log internally; return a generic error message to the client",
                    "CWE-209", "OWASP A09");
        }
    }

    // ── CYBER017: CSRF (CWE-352) ─────────────────────────────────────────────

    static final class RuleCWE352CSRF implements Rule {
        public String id() { return "CYBER017"; }
        public String description() { return "HTTP state-changing action without CSRF token check (CWE-352)."; }

        //fusa:req REQ-CYBER017
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : LintRules.javaFiles(root, cfg)) {
                String name = f.getFileName().toString();
                if (!name.contains("Servlet") && !name.contains("Controller")) continue;
                List<String> lines = LintRules.readLines(f);
                boolean hasDoPost = false;
                boolean hasCsrfCheck = false;
                for (String line : lines) {
                    if (line.contains("doPost") || line.contains("@PostMapping")) hasDoPost = true;
                    if (line.contains("csrf") || line.contains("CSRF") || line.contains("_token")) hasCsrfCheck = true;
                }
                if (hasDoPost && !hasCsrfCheck) {
                    out.add(Finding.builder("CYBER017", Severity.WARNING,
                            "POST handler without CSRF token check — CWE-352",
                            LintRules.loc(root, f, 1))
                            .category(FuSa.Category.security)
                            .standard("CWE-352").clause("352")
                            .remediation("implement CSRF token validation in all state-changing endpoints")
                            .build());
                }
            }
            return out;
        }
    }

    // ── CYBER018: ReDoS (CWE-400) ────────────────────────────────────────────

    static final class RuleCWE400ReDoS implements Rule {
        private static final Pattern CATASTROPHIC_RE = Pattern.compile(
                "Pattern\\.compile\\s*\\(.*(?:\\+\\+|\\*\\*|\\(.*\\+\\)\\*|\\(.*\\*\\)\\+)");

        public String id() { return "CYBER018"; }
        public String description() { return "Potentially catastrophic regex — ReDoS risk (CWE-400)."; }

        //fusa:req REQ-CYBER018
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER018", Severity.WARNING, CATASTROPHIC_RE,
                    "regex with nested quantifiers may cause ReDoS — CWE-400",
                    "simplify the regex; add input length limits; use linear-time matching",
                    "CWE-400", "OWASP A03");
        }
    }

    // ── CYBER019: Resource exhaustion (CWE-770) ───────────────────────────────

    static final class RuleCWE770ResourceExhaustion implements Rule {
        private static final Pattern UNBOUNDED_ALLOC = Pattern.compile(
                "new\\s+byte\\s*\\[\\s*(?:request|input|param|user)");

        public String id() { return "CYBER019"; }
        public String description() { return "Unbounded resource allocation from user-controlled size (CWE-770)."; }

        //fusa:req REQ-CYBER019
        public List<Finding> run(Path root, Config cfg) throws IOException {
            return scanPattern(root, cfg, "CYBER019", Severity.WARNING, UNBOUNDED_ALLOC,
                    "byte array allocated with user-controlled size — CWE-770 resource exhaustion",
                    "enforce maximum allocation limits; validate size against a safe upper bound",
                    "CWE-770", "CERT Java MSC05-J");
        }
    }

    // ── CYBER020: SECURITY.md must be present ─────────────────────────────────

    static final class RuleSECURITYMDPresent implements Rule {
        public String id() { return "CYBER020"; }
        public String description() { return "SECURITY.md must be present (ISO 21434 Ch.10, IEC 62443-4-1)."; }

        //fusa:req REQ-CYBER020
        public List<Finding> run(Path root, Config cfg) {
            for (String name : List.of("SECURITY.md", "SECURITY.txt", "SECURITY")) {
                if (java.nio.file.Files.exists(root.resolve(name))) return List.of();
            }
            return List.of(Finding.builder("CYBER020", Severity.WARNING,
                    "no SECURITY.md found — required for ISO 21434 Ch.10 vulnerability disclosure",
                    new FuSa.Location("SECURITY.md"))
                    .category(FuSa.Category.security)
                    .standard("ISO 21434").clause("10.4")
                    .remediation("add a SECURITY.md with vulnerability reporting process")
                    .build());
        }
    }

    // ── Shared scanner ────────────────────────────────────────────────────────

    static List<Finding> scanPattern(Path root, Config cfg, String ruleId, Severity sev,
            Pattern pat, String msg, String remediation, String standard, String clause) throws IOException {
        List<Finding> out = new ArrayList<>();
        for (Path f : LintRules.javaFiles(root, cfg)) {
            List<String> lines = LintRules.readLines(f);
            for (int i = 0; i < lines.size(); i++) {
                if (pat.matcher(lines.get(i)).find() && !LintRules.hasAnnotation(lines, i, "//fusa:unsafe")) {
                    out.add(Finding.builder(ruleId, sev, msg, LintRules.loc(root, f, i + 1))
                            .category(FuSa.Category.security)
                            .standard(standard).clause(clause)
                            .remediation(remediation)
                            .build());
                }
            }
        }
        return out;
    }
}
