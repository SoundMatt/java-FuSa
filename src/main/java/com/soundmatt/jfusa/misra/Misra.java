package com.soundmatt.jfusa.misra;

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
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * MISRA Java 2023 alignment report — subset of rules applicable to Java.
 */
public final class Misra {

    /** §1.3/§9.3: `<standard>-gap-report.json` — "misra-java" is this tool's own
     *  Java-specific interpretation (§2.4.1 allows ids outside the registry as long as
     *  they are a consistent lowercase id, never a display string). */
    public static final String MISRA_JSON = "misra-java-gap-report.json";

    private static final List<MisraRule> RULES = List.of(
        new MisraRule("MISRA-1.1",  "Avoid implicit narrowing conversions",
                      Pattern.compile("\\(byte\\)|\\(short\\)|\\(char\\)")),
        new MisraRule("MISRA-2.3",  "Avoid dead code (empty blocks that are not documented)",
                      Pattern.compile("\\{\\s*\\}")),
        new MisraRule("MISRA-4.1",  "Do not use System.exit() in library code",
                      Pattern.compile("System\\.exit\\s*\\(")),
        new MisraRule("MISRA-4.3",  "Do not use ThreadDeath or Error subtypes",
                      Pattern.compile("catch\\s*\\(\\s*(Error|ThreadDeath)")),
        new MisraRule("MISRA-5.4",  "Avoid direct field access in external classes (use getters)",
                      Pattern.compile("\\.\\w+\\s*=[^=]")),
        new MisraRule("MISRA-8.6",  "Initialise all variables at declaration",
                      Pattern.compile("\\b(int|long|double|float|boolean)\\s+\\w+\\s*;")),
        new MisraRule("MISRA-15.5", "Return statement should be last in method",
                      Pattern.compile("return[^;]+;[^}]*return"))
    );

    static {
        Engine.DEFAULT.mustRegister(new RuleMisra());
    }

    private Misra() {}
    public static void activate() {}

    record MisraRule(String id, String description, Pattern pattern) {}

    /** §9.3 canonical gap-report — one objective per MISRA rule; `status` is
     *  `satisfied` when no violation was found, `gap` otherwise (this scan is a
     *  binary pattern match, so `partial` never applies). */
    //fusa:req REQ-MISRA001
    public static void generate(Path root) throws IOException {
        List<Object[]> hits = scan(root);
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "gap-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("standard", "misra-java");
        w.key("objectives"); w.arrayStart();
        int satisfied = 0, gaps = 0;
        for (MisraRule r : RULES) {
            boolean violated = hits.stream().anyMatch(h -> h[0].equals(r.id()));
            w.objectStart();
            w.field("id", r.id());
            w.field("title", r.description());
            w.field("clause", r.id());
            w.field("status", violated ? "gap" : "satisfied");
            w.key("evidence"); w.arrayStart(); w.arrayEnd();
            w.key("findings"); w.arrayStart();
            if (violated) w.value("MISRA001");
            w.arrayEnd();
            w.objectEnd();
            if (violated) gaps++; else satisfied++;
        }
        w.arrayEnd();
        w.key("summary"); w.objectStart();
        w.field("total", RULES.size());
        w.field("satisfied", satisfied);
        w.field("partial", 0);
        w.field("gaps", gaps);
        w.objectEnd();
        w.objectEnd();
        Files.writeString(root.resolve(MISRA_JSON), w.toPretty() + "\n");
        System.out.println("MISRA gap-report: " + hits.size() + " violation(s) across " + gaps
                + "/" + RULES.size() + " rule(s) written to " + MISRA_JSON);
    }

    //fusa:req REQ-MISRA001
    public static List<Object[]> scan(Path root) throws IOException {
        List<Path> files = javaFiles(root);
        List<Object[]> hits = new ArrayList<>();
        for (Path f : files) {
            String rel = root.relativize(f).toString();
            List<String> lines = Files.readAllLines(f);
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                for (MisraRule r : RULES) {
                    if (r.pattern().matcher(line).find()) {
                        hits.add(new Object[]{r.id(), rel, i + 1, line.strip()});
                    }
                }
            }
        }
        return hits;
    }

    static List<Path> javaFiles(Path root) throws IOException {
        Path src = root.resolve("src/main/java");
        if (!Files.exists(src)) return List.of();
        try (Stream<Path> s = Files.walk(src)) {
            return s.filter(p -> p.toString().endsWith(".java")).toList();
        }
    }

    static final class RuleMisra implements Rule {
        public String id() { return "MISRA001"; }
        public String description() { return "MISRA Java alignment check."; }

        //fusa:req REQ-MISRA002
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Object[]> hits = scan(root);
            List<Finding> out = new ArrayList<>();
            for (Object[] h : hits) {
                out.add(Finding.builder("MISRA001", Severity.INFO,
                        h[0] + ": " + RULES.stream().filter(r -> r.id().equals(h[0]))
                                .map(MisraRule::description).findFirst().orElse(""),
                        new FuSa.Location((String) h[1], (int) h[2]))
                        .category(FuSa.Category.safety)
                        .standard("misra-java")
                        .build());
            }
            return out;
        }
    }
}
