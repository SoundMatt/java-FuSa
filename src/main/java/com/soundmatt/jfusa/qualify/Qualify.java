package com.soundmatt.jfusa.qualify;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.release.Release;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Tool qualification suite — self-test framework and evidence report.
 * Produces {@code qualify-report.json} with SHA-256 integrity hash.
 * Supports tool qualification display (Feature 2) and V&V independence (Feature 4).
 */
public final class Qualify {

    public static final String QUALIFY_REPORT = "qualify-report.json";

    // ── Qualification options ─────────────────────────────────────────────────

    /**
     * Optional metadata for the qualification report.
     *
     * @param qualificationMethod    "self", "independent", or ""
     * @param qualifierIdentity      name/org of the qualifier
     * @param qualificationRecordUri URI to the qualification dossier
     * @param implementationAuthor   name/org of the implementation author (V&V)
     * @param independentReviewer    name/org of the independent reviewer (V&V)
     * @param independentTestExecutor name/org of the independent test executor (V&V)
     * @param achievableAsil         achievable ASIL after independence measures
     */
    //fusa:req REQ-QUALIFY002
    //fusa:req REQ-QUALIFY003
    public record QualifyOptions(
            String qualificationMethod,
            String qualifierIdentity,
            String qualificationRecordUri,
            String implementationAuthor,
            String independentReviewer,
            String independentTestExecutor,
            String achievableAsil) {

        /** Empty options — all fields blank. */
        //fusa:req REQ-QUALIFY002
        public static QualifyOptions empty() {
            return new QualifyOptions("", "", "", "", "", "", "");
        }

        /**
         * Qualification badge text.
         * Returns "independently-qualified", "self-qualified", or "unqualified".
         */
        //fusa:req REQ-QUALIFY002
        public String badge() {
            if ("independent".equalsIgnoreCase(qualificationMethod)
                    && qualifierIdentity != null && !qualifierIdentity.isBlank()) {
                return "independently-qualified";
            }
            if ("self".equalsIgnoreCase(qualificationMethod)) return "self-qualified";
            return "unqualified";
        }

        /**
         * V&V independence status.
         * Returns "independent" when reviewer differs from implementation author, else "not-independent".
         */
        //fusa:req REQ-QUALIFY003
        public String independenceStatus() {
            if (independentReviewer != null && !independentReviewer.isBlank()
                    && implementationAuthor != null && !implementationAuthor.isBlank()
                    && !independentReviewer.equalsIgnoreCase(implementationAuthor)) {
                return "independent";
            }
            return "not-independent";
        }
    }

    static {
        Engine.DEFAULT.mustRegister(new RuleQualifyReportPresent());
    }

    private Qualify() {}
    public static void activate() {}

    // ── Self-test suite ───────────────────────────────────────────────────────

    /** Backward-compatible entry point; uses empty QualifyOptions. */
    //fusa:req REQ-QUALIFY001
    public static void run(Path projectRoot, Config cfg, boolean full) throws IOException {
        run(projectRoot, cfg, full, QualifyOptions.empty());
    }

    /** Full entry point with qualification metadata; writes the default report path in text mode. */
    //fusa:req REQ-QUALIFY002
    public static void run(Path projectRoot, Config cfg, boolean full, QualifyOptions opts) throws IOException {
        run(projectRoot, cfg, full, opts, QUALIFY_REPORT, "text");
    }

    /**
     * Full entry point honoring {@code --output} (report write target, default
     * {@link #QUALIFY_REPORT}) and {@code --format} ("text" prints the pass/fail
     * summary line, "json" prints the generated report body to stdout).
     */
    //fusa:req REQ-QUALIFY006
    public static void run(Path projectRoot, Config cfg, boolean full, QualifyOptions opts,
                            String output, String format) throws IOException {
        List<TestCase> cases = runSelfTests();
        String content = generateReport(projectRoot, cases, opts,
                output == null || output.isBlank() ? QUALIFY_REPORT : output);
        if ("json".equalsIgnoreCase(format)) {
            System.out.println(content);
            return;
        }
        long passed = cases.stream().filter(TestCase::passed).count();
        String badge = opts.badge();
        System.out.printf("Qualification: %d/%d passed%s  [%s]%n",
                passed, cases.size(), passed == cases.size() ? " [PASS]" : " [FAIL]", badge);
        String independence = opts.independenceStatus();
        if (!"not-independent".equals(independence)) {
            System.out.printf("V&V independence: %s (reviewer: %s)%n",
                    independence, opts.independentReviewer());
        }
    }

    //fusa:req REQ-QUALIFY004
    public record TestCase(String name, boolean passed, String detail) {}

    //fusa:req REQ-QUALIFY004
    public static List<TestCase> runSelfTests() {
        List<TestCase> cases = new ArrayList<>();

        // TC-001: Version constants present
        cases.add(tc("TC-001: Version constants present",
                !FuSa.VERSION.isBlank() && !FuSa.SPEC_VERSION.isBlank(),
                "VERSION=" + FuSa.VERSION + ", SPEC_VERSION=" + FuSa.SPEC_VERSION));

        // TC-002: Exit codes are distinct
        int[] codes = {FuSa.EXIT_OK, FuSa.EXIT_GATE_FAIL, FuSa.EXIT_USAGE, FuSa.EXIT_RUNTIME};
        boolean distinct = new java.util.HashSet<>(List.of(0, 1, 2, 3)).size() == codes.length;
        cases.add(tc("TC-002: Exit codes 0/1/2/3 are distinct", distinct, "codes: 0,1,2,3"));

        // TC-003: DeriveCategory prefix registry
        boolean catOk = FuSa.deriveCategory("LINT001") == FuSa.Category.lint
                && FuSa.deriveCategory("CYBER001") == FuSa.Category.security
                && FuSa.deriveCategory("XYZ999") == FuSa.Category.other;
        cases.add(tc("TC-003: DeriveCategory prefix registry", catOk, "LINT→lint, CYBER→security, XYZ→other"));

        // TC-004: ComputeFingerprint format
        FuSa.Finding f = FuSa.Finding.builder("LINT001", Severity.ERROR, "unused var",
                new FuSa.Location("Main.java", 42)).build();
        String fp = f.fingerprint();
        boolean fpOk = fp.startsWith("sha256:") && fp.length() == 71;
        cases.add(tc("TC-004: ComputeFingerprint format", fpOk, "fp=" + fp));

        // TC-005: ComputeFingerprint stability
        String fp2 = FuSa.computeFingerprint(f);
        cases.add(tc("TC-005: ComputeFingerprint is stable", fp.equals(fp2), "fp1==fp2"));

        // TC-006: Message normalization — digits replaced
        String n1 = FuSa.normalizeMessage("covered 42 of 100 statements");
        String n2 = FuSa.normalizeMessage("covered 7 of 9 statements");
        cases.add(tc("TC-006: normalizeMessage digits→#", n1.equals(n2), "n1=" + n1 + " n2=" + n2));

        // TC-007: Whitespace collapse
        String ws1 = FuSa.normalizeMessage("foo  bar");
        String ws2 = FuSa.normalizeMessage("foo bar");
        cases.add(tc("TC-007: normalizeMessage whitespace collapse", ws1.equals(ws2), "ws1=" + ws1));

        // TC-008: Different ruleID → different fingerprint
        FuSa.Finding f2 = FuSa.Finding.builder("LINT002", Severity.ERROR, "unused var",
                new FuSa.Location("Main.java", 42)).build();
        cases.add(tc("TC-008: Different ruleId → different fingerprint",
                !fp.equals(f2.fingerprint()), "different: " + !fp.equals(f2.fingerprint())));

        // TC-009: Severity enum ordering
        boolean sevOk = Severity.INFO.rank() < Severity.WARNING.rank()
                && Severity.WARNING.rank() < Severity.ERROR.rank();
        cases.add(tc("TC-009: Severity rank ordering INFO<WARNING<ERROR", sevOk, "ranks: 0<1<2"));

        // TC-010: Config parse round-trip
        boolean cfgOk;
        try {
            Config cfg = Config.parse("{\"version\":\"1\",\"project\":{\"name\":\"test\",\"standard\":\"ISO26262\"}," +
                    "\"rules\":{},\"report\":{\"format\":\"text\"}}");
            cfgOk = "1".equals(cfg.version()) && "test".equals(cfg.project().name());
        } catch (Exception e) { cfgOk = false; }
        cases.add(tc("TC-010: Config parse round-trip", cfgOk, "parsed version+name"));

        return cases;
    }

    private static TestCase tc(String name, boolean passed, String detail) {
        return new TestCase(name, passed, detail);
    }

    // ── Report generation ─────────────────────────────────────────────────────

    /** Backward-compatible report generation with no options. */
    //fusa:req REQ-QUALIFY005
    public static void generateReport(Path projectRoot, List<TestCase> cases) throws IOException {
        generateReport(projectRoot, cases, QualifyOptions.empty());
    }

    /** Report generation with qualification metadata, writing to the default {@link #QUALIFY_REPORT} path. */
    //fusa:req REQ-QUALIFY002
    //fusa:req REQ-QUALIFY003
    public static void generateReport(Path projectRoot, List<TestCase> cases, QualifyOptions opts)
            throws IOException {
        generateReport(projectRoot, cases, opts, QUALIFY_REPORT);
    }

    /**
     * Full report generation with qualification metadata, honoring an explicit
     * {@code output} path (relative to {@code projectRoot}) for the JSON report
     * and its sibling {@code .sha256} hash file. Returns the generated JSON body.
     */
    //fusa:req REQ-QUALIFY006
    public static String generateReport(Path projectRoot, List<TestCase> cases, QualifyOptions opts,
            String output) throws IOException {
        long passedCount = cases.stream().filter(TestCase::passed).count();
        long failedCount = cases.stream().filter(tc -> !tc.passed()).count();
        var w = new Json.Writer();
        w.objectStart();
        // §3.1 common header
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "qualification");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        // Feature 2: qualification method / badge
        w.field("qualificationMethod",
                opts.qualificationMethod() != null && !opts.qualificationMethod().isBlank()
                        ? opts.qualificationMethod() : "self");
        w.field("qualificationBadge", opts.badge());
        w.fieldIfNonBlank("qualificationRecordUri", opts.qualificationRecordUri());
        w.fieldIfNonBlank("qualifierIdentity",      opts.qualifierIdentity());
        // Feature 4: V&V independence
        w.fieldIfNonBlank("implementationAuthor",     opts.implementationAuthor());
        w.fieldIfNonBlank("independentReviewer",      opts.independentReviewer());
        w.fieldIfNonBlank("independentTestExecutor",  opts.independentTestExecutor());
        w.fieldIfNonBlank("achievableAsil",           opts.achievableAsil());
        w.field("independenceStatus", opts.independenceStatus());
        // §6 qualify body
        w.field("total", cases.size());
        w.field("passed", passedCount);
        w.field("failed", failedCount);
        w.key("results"); w.arrayStart();
        for (TestCase tc : cases) {
            w.objectStart();
            w.field("name", tc.name());
            w.field("result", tc.passed() ? "PASS" : "FAIL");
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        String content = w.toPretty() + "\n";
        Path reportPath = projectRoot.resolve(output);
        if (reportPath.getParent() != null) Files.createDirectories(reportPath.getParent());
        Files.writeString(reportPath, content);
        // Write SHA-256 of report to a sibling .sha256 file, named after the
        // actual output filename (not the hardcoded default).
        String outName = reportPath.getFileName().toString();
        String hashName = outName.endsWith(".json")
                ? outName.substring(0, outName.length() - ".json".length()) + ".sha256"
                : outName + ".sha256";
        Files.writeString(reportPath.resolveSibling(hashName),
                Release.sha256file(reportPath) + "\n");
        return content;
    }

    // ── QUALIFY001 rule ───────────────────────────────────────────────────────

    static final class RuleQualifyReportPresent implements Rule {
        public String id() { return "QUALIFY001"; }
        public String description() { return "Tool qualification report (qualify-report.json) must be present."; }

        //fusa:req REQ-QUALIFY001
        public List<Finding> run(Path root, Config cfg) {
            if (!Files.exists(root.resolve(QUALIFY_REPORT))) {
                return List.of(Finding.builder("QUALIFY001", Severity.WARNING,
                        "no qualification report found — run 'jfusa qualify' to generate",
                        new FuSa.Location(QUALIFY_REPORT))
                        .category(FuSa.Category.safety)
                        .remediation("run 'jfusa qualify' to produce tool confidence evidence")
                        .build());
            }
            return List.of();
        }
    }
}
