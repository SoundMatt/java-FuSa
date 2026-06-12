package com.soundmatt.jfusa.trace;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.lint.LintRules;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Requirements traceability engine and coverage mapping.
 * Scans for {@code //fusa:req} and {@code //fusa:test} annotations.
 */
public final class Trace {

    private static final Pattern REQ_ANNOT  = Pattern.compile("//fusa:req\\s+(\\S+)");
    private static final Pattern TEST_ANNOT = Pattern.compile("//fusa:test\\s+(\\S+)");
    private static final String REQS_FILE   = ".fusa-reqs.json";

    static {
        Engine.DEFAULT.mustRegister(new RuleTraceability());
    }

    private Trace() {}
    public static void activate() {}

    // ── Annotation scanning ───────────────────────────────────────────────────

    public record Annotation(String reqId, String file, int line, String type) {}

    public static List<Annotation> scanAnnotations(Path root, Config cfg) throws IOException {
        List<Annotation> out = new ArrayList<>();
        for (Path f : LintRules.javaFiles(root, cfg)) {
            List<String> lines = LintRules.readLines(f);
            String rel = root.relativize(f).toString();
            for (int i = 0; i < lines.size(); i++) {
                Matcher rm = REQ_ANNOT.matcher(lines.get(i));
                while (rm.find()) out.add(new Annotation(rm.group(1), rel, i + 1, "impl"));
                Matcher tm = TEST_ANNOT.matcher(lines.get(i));
                while (tm.find()) out.add(new Annotation(tm.group(1), rel, i + 1, "test"));
            }
        }
        return out;
    }

    // ── Traceability matrix ───────────────────────────────────────────────────

    public static Map<String, List<Annotation>> buildMatrix(Path root, Config cfg) throws IOException {
        Map<String, List<Annotation>> matrix = new LinkedHashMap<>();
        for (Annotation a : scanAnnotations(root, cfg)) {
            matrix.computeIfAbsent(a.reqId(), k -> new ArrayList<>()).add(a);
        }
        return matrix;
    }

    public static String renderText(Map<String, List<Annotation>> matrix) {
        if (matrix.isEmpty()) return "No //fusa:req or //fusa:test annotations found.\n";
        var sb = new StringBuilder();
        sb.append("Requirement Traceability Matrix\n");
        sb.append("=".repeat(60)).append('\n');
        for (var e : matrix.entrySet()) {
            sb.append(e.getKey()).append('\n');
            for (Annotation a : e.getValue()) {
                sb.append("  [").append(a.type()).append("] ")
                        .append(a.file()).append(':').append(a.line()).append('\n');
            }
        }
        sb.append("-".repeat(60)).append('\n');
        sb.append("Total requirements annotated: ").append(matrix.size()).append('\n');
        long tested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a ->
                        a.type().equals("test") || a.type().equals("sec-test"))).count();
        long secTested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a -> a.type().equals("sec-test"))).count();
        sb.append("Requirements with test coverage: ").append(tested).append('\n');
        sb.append("Security-tested requirements: ").append(secTested).append('\n');
        if (matrix.size() > 0) {
            sb.append(String.format("Test coverage: %.0f%%\n", 100.0 * tested / matrix.size()));
        }
        return sb.toString();
    }

    /** §5 canonical JSON shape: §3.1 envelope + requirements[] + tags[] + coverage. */
    public static String renderJson(Map<String, List<Annotation>> matrix) {
        var w = new Json.Writer();
        w.objectStart();
        // §3.1 common header
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "trace-matrix");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        // §5 requirements[] — one entry per unique annotated requirement id
        w.key("requirements"); w.arrayStart();
        for (String reqId : matrix.keySet()) {
            w.objectStart();
            w.field("id", reqId);
            w.objectEnd();
        }
        w.arrayEnd();
        // §5 tags[] — flat array; kind MUST be "impl"|"test"|"sec-test"
        w.key("tags"); w.arrayStart();
        for (var e : matrix.entrySet()) {
            for (Annotation a : e.getValue()) {
                w.objectStart();
                w.field("requirementId", a.reqId());
                w.field("file", a.file());
                w.field("line", a.line());
                w.field("kind", a.type());
                w.objectEnd();
            }
        }
        w.arrayEnd();
        // §5 coverage
        int total = matrix.size();
        long traced = matrix.entrySet().stream().filter(e -> !e.getValue().isEmpty()).count();
        long tested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a ->
                        a.type().equals("test") || a.type().equals("sec-test"))).count();
        long secTested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a -> a.type().equals("sec-test"))).count();
        w.key("coverage"); w.objectStart();
        w.field("totalRequirements", total);
        w.field("tracedRequirements", traced);
        w.field("testedRequirements", tested);
        w.field("secTestedRequirements", secTested);
        w.objectEnd();
        w.objectEnd();
        return w.toPretty();
    }

    // ── Gaps report ───────────────────────────────────────────────────────────

    public static List<String> findGaps(Path root, Config cfg) throws IOException {
        Map<String, List<Annotation>> matrix = buildMatrix(root, cfg);
        List<String> gaps = new ArrayList<>();
        for (var e : matrix.entrySet()) {
            boolean hasSrc  = e.getValue().stream().anyMatch(a -> a.type().equals("impl"));
            boolean hasTest = e.getValue().stream().anyMatch(a ->
                    a.type().equals("test") || a.type().equals("sec-test"));
            if (hasSrc && !hasTest) gaps.add(e.getKey());
        }
        return gaps;
    }

    // ── TRACE001 rule ─────────────────────────────────────────────────────────

    static final class RuleTraceability implements Rule {
        public String id() { return "TRACE001"; }
        public String description() { return "All annotated requirements should have at least one //fusa:test reference."; }

        //fusa:req REQ-TRACE001
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<String> gaps = findGaps(root, cfg);
            List<Finding> out = new ArrayList<>();
            for (String reqId : gaps) {
                out.add(Finding.builder("TRACE001", Severity.WARNING,
                        "requirement " + reqId + " has source annotations but no //fusa:test coverage",
                        new FuSa.Location(".fusa-reqs.json"))
                        .category(FuSa.Category.requirement)
                        .remediation("add //fusa:test " + reqId + " in a JUnit test covering this requirement")
                        .build());
            }
            return out;
        }
    }
}
