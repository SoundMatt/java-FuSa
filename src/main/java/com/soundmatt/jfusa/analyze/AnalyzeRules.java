package com.soundmatt.jfusa.analyze;

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
 * Static analysis passes for Java safety (ANA001–ANA006).
 * Registered with the default engine registry at class-load time.
 */
public final class AnalyzeRules {

    static {
        Engine.DEFAULT.mustRegister(new RuleNullDeref());
        Engine.DEFAULT.mustRegister(new RuleUnclosedResource());
        Engine.DEFAULT.mustRegister(new RuleSynchronizedOnNonFinal());
        Engine.DEFAULT.mustRegister(new RuleUnhandledInterruptedException());
        Engine.DEFAULT.mustRegister(new RuleEmptyCatchBlock());
        Engine.DEFAULT.mustRegister(new RuleExceptionSwallowed());
    }

    private AnalyzeRules() {}

    /** Ensure static initialiser runs to register rules. */
    public static void activate() {}

    // ── ANA001: Potential null dereference after nullable return ─────────────

    static final class RuleNullDeref implements Rule {
        private static final Pattern NULLABLE_CALL_THEN_DOT = Pattern.compile(
                "\\b\\w+\\s*\\([^)]*\\)\\.\\w+");

        public String id() { return "ANA001"; }
        public String description() { return "Potential null dereference — chained call without null check."; }

        //fusa:req REQ-ANA001
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : LintRules.javaFiles(root, cfg)) {
                List<String> lines = LintRules.readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i).strip();
                    if (!line.startsWith("//") && NULLABLE_CALL_THEN_DOT.matcher(line).find()
                            && !line.contains("Optional") && !line.contains("//fusa:unsafe")) {
                        out.add(Finding.builder("ANA001", Severity.WARNING,
                                "potential null dereference: chained method call without null check",
                                LintRules.loc(root, f, i + 1))
                                .category(FuSa.Category.safety)
                                .standard("IEC 61508-3").clause("7.4.3")
                                .remediation("add null check or use Optional; annotate with //fusa:unsafe if checked higher up")
                                .build());
                    }
                }
            }
            return out;
        }
    }

    // ── ANA002: Unclosed resource (not in try-with-resources) ─────────────────

    static final class RuleUnclosedResource implements Rule {
        private static final Pattern NEW_CLOSEABLE = Pattern.compile(
                "=\\s*new\\s+(?:FileInputStream|FileOutputStream|BufferedReader|BufferedWriter|" +
                "InputStreamReader|OutputStreamWriter|ZipFile|ZipOutputStream|Scanner)\\s*\\(");

        public String id() { return "ANA002"; }
        public String description() { return "Resource allocation outside try-with-resources — potential resource leak."; }

        //fusa:req REQ-ANA002
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : LintRules.javaFiles(root, cfg)) {
                List<String> lines = LintRules.readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i).strip();
                    if (NEW_CLOSEABLE.matcher(line).find() && !line.startsWith("try")
                            && !LintRules.hasAnnotation(lines, i, "//fusa:unsafe")) {
                        // Check if it's inside a try-with-resources (rough heuristic: look for 'try (' in prev lines)
                        boolean inTryWithRes = false;
                        for (int j = Math.max(0, i - 5); j < i; j++) {
                            if (lines.get(j).contains("try (") || lines.get(j).contains("try(")) {
                                inTryWithRes = true;
                                break;
                            }
                        }
                        if (!inTryWithRes) {
                            out.add(Finding.builder("ANA002", Severity.WARNING,
                                    "resource allocated outside try-with-resources — potential resource leak",
                                    LintRules.loc(root, f, i + 1))
                                    .category(FuSa.Category.safety)
                                    .standard("IEC 61508-3").clause("7.4.3")
                                    .remediation("use try-with-resources: try (var x = new ...) { ... }")
                                    .build());
                        }
                    }
                }
            }
            return out;
        }
    }

    // ── ANA003: Synchronized on non-final field ────────────────────────────────

    static final class RuleSynchronizedOnNonFinal implements Rule {
        private static final Pattern SYNC_FIELD = Pattern.compile(
                "synchronized\\s*\\(\\s*(?!this|\\w+\\.class)([a-z]\\w*)\\s*\\)");

        public String id() { return "ANA003"; }
        public String description() { return "Synchronized block on a potentially non-final field — unsafe lock object."; }

        //fusa:req REQ-ANA003
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : LintRules.javaFiles(root, cfg)) {
                List<String> lines = LintRules.readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    var m = SYNC_FIELD.matcher(lines.get(i));
                    if (m.find() && !LintRules.hasAnnotation(lines, i, "//fusa:unsafe")) {
                        String field = m.group(1);
                        out.add(Finding.builder("ANA003", Severity.WARNING,
                                "synchronized on field '" + field + "' — ensure this is a final lock object",
                                LintRules.loc(root, f, i + 1))
                                .category(FuSa.Category.concurrency)
                                .standard("IEC 61508-3").clause("7.4.11")
                                .remediation("declare the lock field as 'private final Object " + field + " = new Object()'")
                                .build());
                    }
                }
            }
            return out;
        }
    }

    // ── ANA004: Unhandled InterruptedException ─────────────────────────────────

    static final class RuleUnhandledInterruptedException implements Rule {
        private static final Pattern CATCH_IE = Pattern.compile(
                "catch\\s*\\(\\s*InterruptedException\\s+\\w+\\s*\\)");

        public String id() { return "ANA004"; }
        public String description() { return "InterruptedException caught without re-interrupting — breaks thread lifecycle."; }

        //fusa:req REQ-ANA004
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : LintRules.javaFiles(root, cfg)) {
                List<String> lines = LintRules.readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    if (CATCH_IE.matcher(lines.get(i)).find()) {
                        // Look for Thread.currentThread().interrupt() in the catch body
                        boolean reInterrupts = false;
                        for (int j = i + 1; j < Math.min(i + 8, lines.size()); j++) {
                            if (lines.get(j).contains("interrupt()") || lines.get(j).contains("//fusa:unsafe")) {
                                reInterrupts = true;
                                break;
                            }
                            if (lines.get(j).strip().equals("}")) break;
                        }
                        if (!reInterrupts) {
                            out.add(Finding.builder("ANA004", Severity.WARNING,
                                    "InterruptedException swallowed without calling Thread.currentThread().interrupt()",
                                    LintRules.loc(root, f, i + 1))
                                    .category(FuSa.Category.concurrency)
                                    .standard("IEC 61508-3").clause("7.4.11")
                                    .remediation("add Thread.currentThread().interrupt() in catch block, or propagate")
                                    .build());
                        }
                    }
                }
            }
            return out;
        }
    }

    // ── ANA005: Empty catch block ─────────────────────────────────────────────

    static final class RuleEmptyCatchBlock implements Rule {
        public String id() { return "ANA005"; }
        public String description() { return "Empty catch block silently swallows exceptions."; }

        //fusa:req REQ-ANA005
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : LintRules.javaFiles(root, cfg)) {
                List<String> lines = LintRules.readLines(f);
                for (int i = 0; i < lines.size() - 1; i++) {
                    String line = lines.get(i).strip();
                    if (!line.startsWith("catch")) continue;
                    if (LintRules.hasAnnotation(lines, i, "//fusa:unsafe")) continue;
                    // Single-line empty catch: catch (...) {}
                    if (line.endsWith("{}")) {
                        out.add(Finding.builder("ANA005", Severity.ERROR,
                                "empty catch block silently swallows exception",
                                LintRules.loc(root, f, i + 1))
                                .category(FuSa.Category.safety)
                                .standard("IEC 61508-3").clause("7.4.10")
                                .remediation("log or rethrow the exception; add //fusa:unsafe with rationale if intentional")
                                .build());
                    } else if (line.endsWith("{")) {
                        // Multi-line catch: next non-empty line is "}"
                        for (int j = i + 1; j < Math.min(i + 5, lines.size()); j++) {
                            String next = lines.get(j).strip();
                            if (next.isEmpty()) continue;
                            if (next.equals("}")) {
                                out.add(Finding.builder("ANA005", Severity.ERROR,
                                        "empty catch block silently swallows exception",
                                        LintRules.loc(root, f, i + 1))
                                        .category(FuSa.Category.safety)
                                        .standard("IEC 61508-3").clause("7.4.10")
                                        .remediation("log or rethrow the exception; add //fusa:unsafe with rationale if intentional")
                                        .build());
                            }
                            break;
                        }
                    }
                }
            }
            return out;
        }
    }

    // ── ANA006: Exception message swallowed ───────────────────────────────────

    static final class RuleExceptionSwallowed implements Rule {
        private static final Pattern THROW_NEW = Pattern.compile("throw\\s+new\\s+\\w+\\(\"");

        public String id() { return "ANA006"; }
        public String description() { return "Exception thrown with new message but without chaining cause — losing context."; }

        //fusa:req REQ-ANA006
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            for (Path f : LintRules.javaFiles(root, cfg)) {
                List<String> lines = LintRules.readLines(f);
                for (int i = 0; i < lines.size(); i++) {
                    // Inside a catch block, look for throw new X("...") without the cause variable
                    String line = lines.get(i).strip();
                    if (THROW_NEW.matcher(line).find() && !line.contains(", e)") && !line.contains(", ex)")
                            && !line.contains(", cause)") && !line.contains(", t)")
                            && !LintRules.hasAnnotation(lines, i, "//fusa:unsafe")) {
                        // Only flag inside catch blocks
                        for (int j = Math.max(0, i - 10); j < i; j++) {
                            if (lines.get(j).strip().startsWith("catch")) {
                                out.add(Finding.builder("ANA006", Severity.INFO,
                                        "exception thrown without chaining cause — original stack trace may be lost",
                                        LintRules.loc(root, f, i + 1))
                                        .category(FuSa.Category.safety)
                                        .remediation("use throw new X(\"msg\", cause) to preserve the exception chain")
                                        .build());
                                break;
                            }
                        }
                    }
                }
            }
            return out;
        }
    }
}
