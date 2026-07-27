package com.soundmatt.jfusa.lint;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Java safety-oriented coding-standard rules (LINT001–LINT010).
 * Registered with the default engine registry at class-load time.
 */
public final class LintRules {

    static {
        Engine.DEFAULT.mustRegister(new RuleNullReturn());
        Engine.DEFAULT.mustRegister(new RuleSystemExit());
        Engine.DEFAULT.mustRegister(new RuleRawThreadCreation());
        Engine.DEFAULT.mustRegister(new RuleStaticMutableField());
        Engine.DEFAULT.mustRegister(new RuleFloatEquality());
        Engine.DEFAULT.mustRegister(new RuleRecursiveMethod());
        Engine.DEFAULT.mustRegister(new RulePrintlnInNonTest());
        Engine.DEFAULT.mustRegister(new RuleReflectionWithoutAnnotation());
        Engine.DEFAULT.mustRegister(new RuleUncheckedCastWithoutAnnotation());
        Engine.DEFAULT.mustRegister(new RuleDeprecatedApiUsage());
    }

    private LintRules() {}

    /** Ensure static initialiser runs to register rules. */
    public static void activate() {}

    // ── Shared scanner utilities ──────────────────────────────────────────────

    //fusa:req REQ-LINTUTIL001
    public static List<Path> javaFiles(Path root, Config cfg) throws IOException {
        List<Path> out = new ArrayList<>();
        if (!Files.isDirectory(root)) return out;
        try (Stream<Path> walk = Files.walk(root)) {
            walk.filter(p -> p.toString().endsWith(".java") && !isExcluded(p, root, cfg))
                    .forEach(out::add);
        }
        return out;
    }

    private static boolean isExcluded(Path p, Path root, Config cfg) {
        String rel = root.relativize(p).toString();
        if (rel.contains("test") || rel.contains("Test")) return false; // include test files
        return false; // honour cfg.rules().exclude patterns if needed
    }

    //fusa:req REQ-LINTUTIL001
    public static List<String> readLines(Path f) throws IOException {
        return Files.readAllLines(f, java.nio.charset.StandardCharsets.UTF_8);
    }

    //fusa:req REQ-LINTUTIL001
    public static FuSa.Location loc(Path root, Path file, int line) {
        return new FuSa.Location(root.relativize(file).toString(), line);
    }

    //fusa:req REQ-LINTUTIL001
    public static boolean hasAnnotation(List<String> lines, int lineIdx, String ann) {
        // Check the line itself and a small look-back window for fusa annotations
        for (int i = Math.max(0, lineIdx - 3); i <= lineIdx && i < lines.size(); i++) {
            if (lines.get(i).contains(ann)) return true;
        }
        return false;
    }

    // ── LINT001: Returning null from a non-void method ────────────────────────

    static final class RuleNullReturn implements Rule {
        private static final Pattern RETURN_NULL = Pattern.compile("\\breturn\\s+null\\s*;");

        public String id() { return "LINT001"; }
        public String description() { return "Returning null from methods — prefer Optional or sentinel values in safety code."; }

        //fusa:req REQ-LINT001
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : javaFiles(root, cfg)) {
                List<String> lines = readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i).strip();
                    if (RETURN_NULL.matcher(line).find() && !hasAnnotation(lines, i, "//fusa:unsafe")) {
                        out.add(Finding.builder("LINT001", Severity.WARNING,
                                "returning null — use Optional<T> or a sentinel value in safety-critical code",
                                loc(root, f, i + 1))
                                .category(FuSa.Category.lint)
                                .remediation("replace with Optional.empty(), throw, or a sentinel constant; add //fusa:unsafe to suppress")
                                .build());
                    }
                }
            }
            return out;
        }
    }

    // ── LINT002: System.exit() without //fusa:safe-state annotation ──────────

    static final class RuleSystemExit implements Rule {
        private static final Pattern SYSEXIT = Pattern.compile("\\bSystem\\.exit\\s*\\(");

        public String id() { return "LINT002"; }
        public String description() { return "System.exit() calls must be annotated //fusa:safe-state to document intentional safe-state entry."; }

        //fusa:req REQ-LINT002
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : javaFiles(root, cfg)) {
                List<String> lines = readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    if (SYSEXIT.matcher(lines.get(i)).find()
                            && !hasAnnotation(lines, i, "//fusa:safe-state")) {
                        out.add(Finding.builder("LINT002", Severity.ERROR,
                                "System.exit() requires //fusa:safe-state annotation (safe-state design clause)",
                                loc(root, f, i + 1))
                                .category(FuSa.Category.lint)
                                .standard("IEC 61508-3").clause("7.4.10")
                                .remediation("add //fusa:safe-state comment explaining the safe-state transition")
                                .build());
                    }
                }
            }
            return out;
        }
    }

    // ── LINT003: Raw Thread creation ──────────────────────────────────────────

    static final class RuleRawThreadCreation implements Rule {
        private static final Pattern NEW_THREAD = Pattern.compile("new\\s+Thread\\s*\\(");

        public String id() { return "LINT003"; }
        public String description() { return "Raw Thread creation — use ExecutorService or a safety-rated ThreadFactory."; }

        //fusa:req REQ-LINT003
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : javaFiles(root, cfg)) {
                List<String> lines = readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    if (NEW_THREAD.matcher(lines.get(i)).find()
                            && !hasAnnotation(lines, i, "//fusa:unsafe")) {
                        out.add(Finding.builder("LINT003", Severity.WARNING,
                                "raw new Thread() — use Executors.newFixedThreadPool() or a named ThreadFactory",
                                loc(root, f, i + 1))
                                .category(FuSa.Category.lint)
                                .standard("IEC 61508-3").clause("7.4.11")
                                .remediation("use ExecutorService for controlled lifecycle; add //fusa:unsafe to suppress")
                                .build());
                    }
                }
            }
            return out;
        }
    }

    // ── LINT004: Static mutable field without //fusa:shared ──────────────────

    static final class RuleStaticMutableField implements Rule {
        private static final Pattern STATIC_MUTABLE = Pattern.compile(
                "\\bstatic\\b(?!.*\\bfinal\\b).*(?:List|Map|Set|ArrayList|HashMap|HashSet|\\[\\])\\s+\\w+");

        public String id() { return "LINT004"; }
        public String description() { return "Static mutable fields require //fusa:shared annotation (thread-safety contract)."; }

        //fusa:req REQ-LINT004
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : javaFiles(root, cfg)) {
                List<String> lines = readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    if (STATIC_MUTABLE.matcher(line).find()
                            && !line.contains("final")
                            && !hasAnnotation(lines, i, "//fusa:shared")) {
                        out.add(Finding.builder("LINT004", Severity.WARNING,
                                "static mutable field requires //fusa:shared annotation documenting thread-safety contract",
                                loc(root, f, i + 1))
                                .category(FuSa.Category.lint)
                                .standard("IEC 61508-3").clause("7.4.11")
                                .remediation("add //fusa:shared with synchronisation strategy, or make final/immutable")
                                .build());
                    }
                }
            }
            return out;
        }
    }

    // ── LINT005: Float/double == comparison ───────────────────────────────────

    static final class RuleFloatEquality implements Rule {
        private static final Pattern FLOAT_EQ = Pattern.compile(
                "\\b(?:float|double)\\b.*==|==.*\\b(?:float|double)\\b|\\d+\\.\\d*[fFdD]?\\s*==|==\\s*\\d+\\.\\d*");

        public String id() { return "LINT005"; }
        public String description() { return "Floating-point equality comparison — use epsilon-based comparison in safety code."; }

        //fusa:req REQ-LINT005
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : javaFiles(root, cfg)) {
                List<String> lines = readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i).strip();
                    if (!line.startsWith("//") && FLOAT_EQ.matcher(line).find()
                            && !hasAnnotation(lines, i, "//fusa:unsafe")) {
                        out.add(Finding.builder("LINT005", Severity.WARNING,
                                "floating-point == comparison is unreliable in safety-critical code",
                                loc(root, f, i + 1))
                                .category(FuSa.Category.lint)
                                .standard("MISRA Java").clause("15.7")
                                .remediation("use Math.abs(a - b) < EPSILON; add //fusa:unsafe to suppress")
                                .build());
                    }
                }
            }
            return out;
        }
    }

    // ── LINT006: Recursive method without depth annotation ───────────────────

    static final class RuleRecursiveMethod implements Rule {
        public String id() { return "LINT006"; }
        public String description() { return "Recursive methods require //fusa:recursive <max-depth> annotation for stack-overflow safety."; }

        //fusa:req REQ-LINT006
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : javaFiles(root, cfg)) {
                List<String> lines = readLines(f);
                // Simple heuristic: a method that calls itself (same simple name within method body)
                String currentMethod = null;
                int braceDepth = 0;
                int methodStartLine = 0;
                boolean inMethod = false;
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    // Detect method declaration (rough heuristic)
                    if (!inMethod && line.matches(".*\\b(public|private|protected)\\b.*\\w+\\s*\\(.*\\).*\\{.*")) {
                        var m = java.util.regex.Pattern.compile("\\b(\\w+)\\s*\\(").matcher(line);
                        if (m.find()) {
                            currentMethod = m.group(1);
                            inMethod = true;
                            braceDepth = 1;
                            methodStartLine = i;
                        }
                    } else if (inMethod) {
                        braceDepth += line.chars().filter(c -> c == '{').count();
                        braceDepth -= line.chars().filter(c -> c == '}').count();
                        if (currentMethod != null && line.contains(currentMethod + "(")
                                && !line.strip().startsWith("//")) {
                            // Recursive call found
                            if (!hasAnnotation(lines, methodStartLine, "//fusa:recursive")) {
                                out.add(Finding.builder("LINT006", Severity.WARNING,
                                        "recursive method '" + currentMethod + "' requires //fusa:recursive <max-depth> annotation",
                                        loc(root, f, methodStartLine + 1))
                                        .category(FuSa.Category.lint)
                                        .standard("JSF++").clause("119")
                                        .remediation("add //fusa:recursive <max-depth> above the method declaration")
                                        .build());
                                currentMethod = null; // report once per method
                            }
                        }
                        if (braceDepth <= 0) { inMethod = false; currentMethod = null; }
                    }
                }
            }
            return out;
        }
    }

    // ── LINT007: System.out.println in non-test code ──────────────────────────

    static final class RulePrintlnInNonTest implements Rule {
        private static final Pattern PRINTLN = Pattern.compile("\\bSystem\\.(out|err)\\.print");

        public String id() { return "LINT007"; }
        public String description() { return "System.out.println / System.err.print in production code — use a structured logger."; }

        //fusa:req REQ-LINT007
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : javaFiles(root, cfg)) {
                String rel = root.relativize(f).toString();
                // Allow in test code (directory-based, not filename-based)
                String relNorm = rel.replace('\\', '/');
                if (relNorm.contains("/test/") || relNorm.startsWith("test/")) continue;
                List<String> lines = readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    if (PRINTLN.matcher(lines.get(i)).find()
                            && !hasAnnotation(lines, i, "//fusa:unsafe")) {
                        out.add(Finding.builder("LINT007", Severity.INFO,
                                "System.out/err used in non-test source — use a structured logging framework",
                                loc(root, f, i + 1))
                                .category(FuSa.Category.style)
                                .remediation("replace with java.util.logging.Logger or a safety-rated logging API")
                                .build());
                    }
                }
            }
            return out;
        }
    }

    // ── LINT008: Reflection without //fusa:reflect ────────────────────────────

    static final class RuleReflectionWithoutAnnotation implements Rule {
        private static final Pattern REFLECT = Pattern.compile(
                "Class\\.forName|getDeclaredMethod|getDeclaredField|getMethod|invoke\\s*\\(");

        public String id() { return "LINT008"; }
        public String description() { return "Reflection requires //fusa:reflect annotation — traceability impact in safety cases."; }

        //fusa:req REQ-LINT008
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : javaFiles(root, cfg)) {
                List<String> lines = readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    if (REFLECT.matcher(lines.get(i)).find()
                            && !hasAnnotation(lines, i, "//fusa:reflect")
                            && !hasAnnotation(lines, i, "//fusa:unsafe")) {
                        out.add(Finding.builder("LINT008", Severity.WARNING,
                                "reflection usage requires //fusa:reflect annotation (traceability risk)",
                                loc(root, f, i + 1))
                                .category(FuSa.Category.lint)
                                .standard("IEC 61508-3").clause("7.4.3")
                                .remediation("add //fusa:reflect with justification; consider refactoring to avoid reflection")
                                .build());
                    }
                }
            }
            return out;
        }
    }

    // ── LINT009: Unchecked casts without annotation ───────────────────────────

    static final class RuleUncheckedCastWithoutAnnotation implements Rule {
        private static final Pattern UNCHECKED = Pattern.compile("@SuppressWarnings.*unchecked");

        public String id() { return "LINT009"; }
        public String description() { return "@SuppressWarnings(\"unchecked\") — verify cast safety in safety-critical code."; }

        //fusa:req REQ-LINT009
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : javaFiles(root, cfg)) {
                List<String> lines = readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    if (UNCHECKED.matcher(lines.get(i)).find()
                            && !hasAnnotation(lines, i, "//fusa:unsafe")) {
                        out.add(Finding.builder("LINT009", Severity.INFO,
                                "@SuppressWarnings(\"unchecked\") — verify type safety and add //fusa:unsafe with justification",
                                loc(root, f, i + 1))
                                .category(FuSa.Category.lint)
                                .remediation("add //fusa:unsafe comment explaining why this cast is safe")
                                .build());
                    }
                }
            }
            return out;
        }
    }

    // ── LINT010: Deprecated API usage ─────────────────────────────────────────

    static final class RuleDeprecatedApiUsage implements Rule {
        public String id() { return "LINT010"; }
        public String description() { return "Usage of @Deprecated APIs should be tracked and migrated in safety-critical code."; }

        //fusa:req REQ-LINT010
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : javaFiles(root, cfg)) {
                List<String> lines = readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    if (line.contains("@Deprecated") && !line.strip().startsWith("//")) {
                        out.add(Finding.builder("LINT010", Severity.INFO,
                                "@Deprecated annotation — plan migration before safety certification",
                                loc(root, f, i + 1))
                                .category(FuSa.Category.lint)
                                .remediation("migrate to the recommended replacement API or add waiver via disposition")
                                .build());
                    }
                }
            }
            return out;
        }
    }
}
