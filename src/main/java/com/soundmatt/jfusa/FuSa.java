package com.soundmatt.jfusa;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Root package of java-FuSa, the functional safety enablement toolkit for Java projects.
 *
 * <p>Exports sentinel exceptions and core value types shared across all sub-packages.
 * Use the sub-packages (config, engine, report, lint, analyze) for concrete functionality.
 *
 * @see <a href="https://github.com/SoundMatt/java-FuSa">java-FuSa</a>
 */
public final class FuSa {

    /** Current release of java-FuSa. */
    public static final String VERSION = "0.4.8";

    /** x-FuSa spec version this release implements. */
    public static final String SPEC_VERSION = "1.10.12";

    // § 2.3 exit codes
    /** Success — no gate failure. */
    public static final int EXIT_OK = 0;
    /** Gate failure — tool ran, found problems. */
    public static final int EXIT_GATE_FAIL = 1;
    /** Usage error — bad flag or argument. */
    public static final int EXIT_USAGE = 2;
    /** Runtime/internal error — could not complete analysis. */
    public static final int EXIT_RUNTIME = 3;

    private FuSa() {}

    // ── Sentinel exceptions ───────────────────────────────────────────────────

    //fusa:req REQ-ERR001
    public static final class NoConfigException extends RuntimeException {
        public NoConfigException(String msg) { super("jfusa: no configuration file found: " + msg); }
        public NoConfigException(String msg, Throwable cause) { super("jfusa: no configuration file found: " + msg, cause); }
    }

    //fusa:req REQ-ERR002
    public static final class InvalidConfigException extends RuntimeException {
        public InvalidConfigException(String msg) { super("jfusa: invalid configuration: " + msg); }
    }

    //fusa:req REQ-ERR003
    public static final class CheckFailedException extends RuntimeException {
        public CheckFailedException(String msg) { super("jfusa: one or more safety checks failed: " + msg); }
    }

    // ── Severity ──────────────────────────────────────────────────────────────

    /** Ranks the importance of a {@link Finding}. */
    public enum Severity {
        INFO, WARNING, ERROR;

        //fusa:req REQ-NF002
        public int rank() {
            return switch (this) {
                case INFO -> 0;
                case WARNING -> 1;
                case ERROR -> 2;
            };
        }
    }

    // ── Category ─────────────────────────────────────────────────────────────

    /** Closed enum of finding categories (§4). */
    public enum Category {
        lint, style, safety, security, coverage, requirement, concurrency,
        SUPPLY_CHAIN("supply-chain"), config, other;

        private final String jsonValue;

        Category() { this.jsonValue = name().toLowerCase(); }
        Category(String jsonValue) { this.jsonValue = jsonValue; }

        //fusa:req REQ-NF003
        public String jsonValue() { return jsonValue; }

        @Override public String toString() { return jsonValue; }
    }

    // ── Disposition ───────────────────────────────────────────────────────────

    /** Records a waiver decision on a finding (§4.1). */
    public enum Disposition {
        open, accepted, deferred, rejected
    }

    // ── Location ─────────────────────────────────────────────────────────────

    //fusa:req REQ-NF001
    public record Location(
            String file,
            int line,
            int column,
            int endLine,
            int endColumn
    ) {
        public Location(String file) { this(file, 0, 0, 0, 0); }
        public Location(String file, int line) { this(file, line, 0, 0, 0); }
        public Location(String file, int line, int column) { this(file, line, column, 0, 0); }
    }

    // ── Finding ───────────────────────────────────────────────────────────────

    /** A single observation produced by a Rule. */
    //fusa:req REQ-NF001
    public record Finding(
            String ruleId,
            Severity severity,
            String message,
            Location location,
            Category category,
            String standard,
            String clause,
            String remediation,
            Disposition disposition,
            String fingerprint
    ) {
        public Finding {
            if (ruleId == null || ruleId.isBlank()) throw new IllegalArgumentException("ruleId must not be blank");
            if (severity == null) throw new IllegalArgumentException("severity must not be null");
            if (message == null) throw new IllegalArgumentException("message must not be null");
            if (location == null) throw new IllegalArgumentException("location must not be null");
        }

        //fusa:req REQ-NF004
        public static Builder builder(String ruleId, Severity severity, String message, Location location) {
            return new Builder(ruleId, severity, message, location);
        }

        public static final class Builder {
            private final String ruleId;
            private final Severity severity;
            private final String message;
            private final Location location;
            private Category category = Category.other;
            private String standard = "";
            private String clause = "";
            private String remediation = "";
            private Disposition disposition = Disposition.open;
            private String fingerprint = "";

            Builder(String ruleId, Severity severity, String message, Location location) {
                this.ruleId = ruleId; this.severity = severity;
                this.message = message; this.location = location;
            }

            //fusa:req REQ-NF004
            public Builder category(Category c) { this.category = c; return this; }
            //fusa:req REQ-NF004
            public Builder standard(String s) { this.standard = s; return this; }
            //fusa:req REQ-NF004
            public Builder clause(String c) { this.clause = c; return this; }
            //fusa:req REQ-NF004
            public Builder remediation(String r) { this.remediation = r; return this; }
            //fusa:req REQ-NF005
            public Builder disposition(Disposition d) { this.disposition = d; return this; }
            //fusa:req REQ-NF005
            public Builder fingerprint(String fp) { this.fingerprint = fp; return this; }

            //fusa:req REQ-NF004
            public Finding build() {
                Finding f = new Finding(ruleId, severity, message, location, category,
                        standard, clause, remediation, disposition, fingerprint);
                return f.fingerprint().isBlank()
                        ? new Finding(ruleId, severity, message, location, category,
                                standard, clause, remediation, disposition, computeFingerprint(f))
                        : f;
            }
        }
    }

    // ── DeriveCategory ────────────────────────────────────────────────────────

    /**
     * Returns the category for a rule id using the §1.5.1 prefix registry.
     * Rules with no recognised prefix map to {@link Category#other}.
     */
    //fusa:req REQ-NF001
    public static Category deriveCategory(String ruleId) {
        if (ruleId == null || ruleId.isBlank()) return Category.other;
        String upper = ruleId.toUpperCase();
        int cut = -1;
        for (int i = 0; i < upper.length(); i++) {
            char c = upper.charAt(i);
            if (Character.isDigit(c) || c == '-') { cut = i; break; }
        }
        String prefix = cut > 0 ? upper.substring(0, cut) : upper;
        return switch (prefix) {
            case "LINT"    -> Category.lint;
            case "STYLE"   -> Category.style;
            case "FUSA"    -> Category.safety;
            case "SEC", "CWE", "CYBER" -> Category.security;
            case "COV"     -> Category.coverage;
            case "REQ", "TRACE" -> Category.requirement;
            case "CONC", "RACE" -> Category.concurrency;
            case "SBOM", "SLSA", "VULN", "RELEASE" -> Category.SUPPLY_CHAIN;
            case "CFG"     -> Category.config;
            case "ISO", "IEC", "DO", "MISRA", "AUTOSAR", "CERT", "UNECE" -> Category.safety;
            case "ANA"     -> Category.safety;
            case "HARA", "TARA" -> Category.safety;
            default        -> Category.other;
        };
    }

    // ── ComputeFingerprint ────────────────────────────────────────────────────

    /**
     * Returns the canonical §4.2 SHA-256 fingerprint for a finding.
     * The finding's location.file MUST already be project-relative before calling.
     */
    //fusa:req REQ-NF001
    public static String computeFingerprint(Finding f) {
        String norm = normalizeMessage(f.message());
        String canonical = f.ruleId() + "" + f.location().file() + "" + norm;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Replaces runs of ASCII digits with "#", collapses whitespace, and trims.
     * NFC normalisation for non-ASCII is left to the caller (ASCII-only tools need
     * no Unicode dependency per §4.2).
     */
    //fusa:req REQ-NF006
    public static String normalizeMessage(String msg) {
        if (msg == null || msg.isEmpty()) return "";
        StringBuilder sb = new StringBuilder(msg.length());
        boolean inDigits = false;
        boolean inSpace = false;
        for (int i = 0; i < msg.length(); i++) {
            char c = msg.charAt(i);
            if (c >= '0' && c <= '9') {
                if (!inDigits) {
                    if (inSpace && !sb.isEmpty()) sb.append(' ');
                    sb.append('#');
                    inDigits = true;
                }
                inSpace = false;
            } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                inDigits = false;
                inSpace = true;
            } else {
                if (inSpace && !sb.isEmpty()) sb.append(' ');
                sb.append(c);
                inDigits = false;
                inSpace = false;
            }
        }
        return sb.toString().strip();
    }
}
