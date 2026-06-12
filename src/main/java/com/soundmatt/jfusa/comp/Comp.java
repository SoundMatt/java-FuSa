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
 * Threshold: ≤10 per method for DAL-C/D; ≤5 for DAL-A/B.
 */
public final class Comp {

    public static final String COMP_JSON = "comp-report.json";
    static final int THRESHOLD = 10;

    private static final Pattern BRANCH = Pattern.compile(
            "\\b(if|else\\s+if|for|while|do|case|catch|&&|\\|\\|)\\b|\\?");

    static {
        Engine.DEFAULT.mustRegister(new RuleComplexityGate());
    }

    private Comp() {}
    public static void activate() {}

    public record MethodComplexity(String file, String method, int complexity, int line) {}

    public static List<MethodComplexity> analyze(Path root) throws IOException {
        List<MethodComplexity> results = new ArrayList<>();
        List<Path> files = javaFiles(root);
        for (Path f : files) {
            String rel = root.relativize(f).toString();
            List<String> lines = Files.readAllLines(f);
            String currentMethod = null;
            int methodLine = 0;
            int complexity = 1;
            int braceDepth = 0;
            int methodDepth = -1;

            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                // Detect method declarations
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
                    if (currentMethod != null) {
                        results.add(new MethodComplexity(rel, currentMethod, complexity, methodLine));
                    }
                    currentMethod = null; methodDepth = -1; complexity = 1;
                }
            }
        }
        return results;
    }

    static String extractMethodName(String line) {
        var m = Pattern.compile("(?:public|private|protected)\\s+\\S+\\s+(\\w+)\\s*\\(").matcher(line);
        return m.find() ? m.group(1) : "unknown";
    }

    public static void generate(Path root) throws IOException {
        List<MethodComplexity> results = analyze(root);
        long over = results.stream().filter(r -> r.complexity() > THRESHOLD).count();
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-comp-1.0");
        w.field("standard", "DO-178C §6.3.4");
        w.field("timestamp", Instant.now().toString());
        w.field("threshold", THRESHOLD);
        w.field("methodCount", results.size());
        w.field("overThreshold", over);
        w.key("methods"); w.arrayStart();
        for (MethodComplexity r : results) {
            w.objectStart();
            w.field("file", r.file()); w.field("method", r.method());
            w.field("complexity", r.complexity()); w.field("line", r.line());
            w.field("status", r.complexity() > THRESHOLD ? "FAIL" : "PASS");
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(COMP_JSON), w.toPretty() + "\n");
        System.out.printf("Complexity: %d methods, %d over threshold=%d%n", results.size(), over, THRESHOLD);
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
        public String description() { return "Cyclomatic complexity ≤10 per method."; }

        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<MethodComplexity> results = analyze(root);
            List<Finding> out = new ArrayList<>();
            for (MethodComplexity r : results) {
                if (r.complexity() > THRESHOLD) {
                    out.add(Finding.builder("COMP001", Severity.WARNING,
                            String.format("method '%s' has cyclomatic complexity %d (threshold %d)",
                                    r.method(), r.complexity(), THRESHOLD),
                            new FuSa.Location(r.file(), r.line()))
                            .category(FuSa.Category.safety)
                            .standard("DO-178C").clause("§6.3.4")
                            .remediation("refactor to reduce branching complexity below " + THRESHOLD)
                            .build());
                }
            }
            return out;
        }
    }
}
