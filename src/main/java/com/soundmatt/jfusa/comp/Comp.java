package com.soundmatt.jfusa.comp;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Cyclomatic complexity analysis (DO-178C §6.3.4 / McCabe metric).
 *
 * <p>DAL-level thresholds (§9.2): A≤4, B≤10 (default), C≤15, D≤20.
 * Output: {@code comp-report.json}, kind {@code "comp-report"} per spec v1.10 §9.2.
 */
public final class Comp {

    public static final String COMP_JSON = "comp-report.json";
    public static final int DEFAULT_THRESHOLD = 10;

    private static final Pattern BRANCH = Pattern.compile(
            "\\b(if|else\\s+if|for|while|do|case|catch|&&|\\|\\|)\\b|\\?");

    static {
        Engine.DEFAULT.mustRegister(new RuleComplexityGate());
    }

    private Comp() {}
    public static void activate() {}

    //fusa:req REQ-COMP001
    public record MethodComplexity(String file, String method, int complexity, int line) {}

    /** Resolve threshold from DAL string per §9.2. */
    //fusa:req REQ-COMP002
    public static int thresholdForDal(String dal) {
        if (dal == null) return DEFAULT_THRESHOLD;
        return switch (dal.toUpperCase()) {
            case "DAL-A" -> 4;
            case "DAL-B" -> 10;
            case "DAL-C" -> 15;
            case "DAL-D" -> 20;
            default -> DEFAULT_THRESHOLD;
        };
    }

    //fusa:req REQ-COMP003
    public static List<MethodComplexity> analyze(Path root) throws IOException {
        List<MethodComplexity> results = new ArrayList<>();
        List<Path> files = javaFiles(root);
        for (Path f : files) {
            String rel = root.relativize(f).toString().replace('\\', '/');
            List<String> lines = Files.readAllLines(f);
            String currentMethod = null;
            int methodLine = 0;
            int complexity = 1;
            int braceDepth = 0;
            int methodDepth = -1;

            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                if (line.matches(".*\\b(public|private|protected)\\b.*\\(.*\\).*\\{.*")) {
                    if (methodDepth < 0) {
                        currentMethod = extractMethodName(line);
                        methodLine = i + 1;
                        complexity = 1;
                        methodDepth = braceDepth;
                    }
                }
                var m = BRANCH.matcher(line);
                while (m.find()) complexity++;
                braceDepth += line.chars().filter(c -> c == '{').count();
                braceDepth -= line.chars().filter(c -> c == '}').count();
                if (methodDepth >= 0 && braceDepth <= methodDepth) {
                    if (currentMethod != null)
                        results.add(new MethodComplexity(rel, currentMethod, complexity, methodLine));
                    currentMethod = null; methodDepth = -1; complexity = 1;
                }
            }
        }
        return results;
    }

    /** The method/constructor name is always the identifier immediately (whitespace-only) before
     *  the parameter list's opening paren, regardless of how many modifier/generic/return-type
     *  tokens precede it — so this doesn't need to enumerate every legal signature shape the way
     *  the previous single-token-return-type regex did (which silently fell back to "unknown" for
     *  {@code public static List<Entry> load(...)}-style multi-token return types and no-arg
     *  constructors — x-FuSa/java-FuSa#35). Matching is restricted to the text before the line's
     *  first {@code '{'} so a same-line method body (e.g. {@code public void run() { helper(); }})
     *  can't have its body's call expression mistaken for the declaration itself; the last match in
     *  that prefix is taken so a same-line annotation call (e.g. {@code @Deprecated(since="1.0")})
     *  doesn't win over the real declaration to its right. */
    private static final Pattern METHOD_NAME_BEFORE_PAREN = Pattern.compile("(\\w+)\\s*\\(");

    //fusa:req REQ-COMP006
    public static String extractMethodName(String line) {
        int brace = line.indexOf('{');
        String signature = brace >= 0 ? line.substring(0, brace) : line;
        var m = METHOD_NAME_BEFORE_PAREN.matcher(signature);
        String name = null;
        while (m.find()) name = m.group(1);
        return name != null ? name : "unknown";
    }

    /** Generate comp-report.json with canonical §9.2 / §3.1 shape. */
    //fusa:req REQ-COMP004
    public static void generate(Path root, int threshold, String dal) throws IOException {
        List<MethodComplexity> results = analyze(root);
        long violations = results.stream().filter(r -> r.complexity() > threshold).count();
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "comp-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("threshold", threshold);
        if (dal != null && !dal.isBlank()) w.field("dal", dal);
        w.field("totalFunctions", results.size());
        w.field("violations", violations);
        w.key("results"); w.arrayStart();
        for (MethodComplexity r : results) {
            w.objectStart();
            w.field("file", r.file());
            w.field("line", r.line());
            w.field("name", r.method());
            w.field("complexity", r.complexity());
            w.field("exceedsThreshold", r.complexity() > threshold);
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(COMP_JSON), w.toPretty() + "\n");
        System.out.printf("Complexity: %d functions, %d violation(s) (threshold=%d%s)%n",
                results.size(), violations, threshold, dal != null && !dal.isBlank() ? " / " + dal : "");
    }

    /** Overload for backwards-compat calls without DAL. */
    //fusa:req REQ-COMP004
    public static void generate(Path root) throws IOException {
        generate(root, DEFAULT_THRESHOLD, null);
    }

    static List<Path> javaFiles(Path root) throws IOException {
        Path src = root.resolve("src/main/java");
        if (!Files.exists(src)) return List.of();
        try (Stream<Path> s = Files.walk(src)) {
            return s.filter(p -> p.toString().endsWith(".java")).toList();
        }
    }

    static final class RuleComplexityGate implements Rule {
        public String id() { return "COMP001"; }
        public String description() { return "Cyclomatic complexity must not exceed threshold per function."; }

        //fusa:req REQ-COMP005
        public List<Finding> run(Path root, Config cfg) throws IOException {
            int threshold = DEFAULT_THRESHOLD;
            List<MethodComplexity> results = analyze(root);
            List<Finding> out = new ArrayList<>();
            for (MethodComplexity r : results) {
                if (r.complexity() > threshold) {
                    out.add(Finding.builder("COMP001", Severity.WARNING,
                            String.format("method '%s' has cyclomatic complexity %d (threshold %d)",
                                    r.method(), r.complexity(), threshold),
                            new FuSa.Location(r.file(), r.line()))
                            .category(FuSa.Category.safety)
                            .standard("do178c").clause("6.3.4")
                            .remediation("refactor to reduce branching complexity below " + threshold)
                            .build());
                }
            }
            return out;
        }
    }
}
