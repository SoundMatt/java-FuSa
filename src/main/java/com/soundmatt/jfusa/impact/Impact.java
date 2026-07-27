package com.soundmatt.jfusa.impact;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Change impact analysis — identifies which requirements, tests, and modules
 * are affected by changed files (via git diff or explicit file list).
 */
public final class Impact {

    public static final String IMPACT_JSON = "impact-report.json";

    private Impact() {}

    //fusa:req REQ-IMPACT001
    public record ImpactResult(List<String> changedFiles, List<String> affectedReqs,
                               List<String> affectedTests, List<String> summary) {}

    //fusa:req REQ-IMPACT001
    public static ImpactResult analyze(Path root, List<String> changedFiles) throws IOException {
        List<String> affectedReqs = new ArrayList<>();
        List<String> affectedTests = new ArrayList<>();
        List<String> summary = new ArrayList<>();

        Path reqs = root.resolve(".fusa-reqs.json");
        if (Files.exists(reqs)) {
            try {
                Map<String, Object> doc = Json.parseObject(Files.readString(reqs));
                List<Object> requirements = Json.arr(doc, "requirements");
                for (Object r : requirements) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> req = (Map<String, Object>) r;
                    String id = Json.str(req, "id", "");
                    String file = Json.str(req, "file", "");
                    if (!file.isEmpty() && changedFiles.stream().anyMatch(cf -> cf.contains(file))) {
                        affectedReqs.add(id);
                    }
                }
            } catch (Exception ignored) {}
        }

        for (String cf : changedFiles) {
            String base = cf.replaceAll("src/main/java/", "src/test/java/")
                            .replaceAll("\\.java$", "Test.java");
            if (Files.exists(root.resolve(base))) {
                affectedTests.add(base);
            }
            if (cf.contains("Rule") || cf.contains("Engine")) {
                summary.add("Safety rule change detected in " + cf + " — re-qualify required");
            }
        }

        summary.add(String.format("%d file(s) changed, %d req(s) potentially affected, %d test(s) identified",
                changedFiles.size(), affectedReqs.size(), affectedTests.size()));
        return new ImpactResult(changedFiles, affectedReqs, affectedTests, summary);
    }

    //fusa:req REQ-IMPACT001
    public static void generate(Path root, List<String> changedFiles) throws IOException {
        ImpactResult r = analyze(root, changedFiles);
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "impact-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.key("changedFiles"); w.arrayStart();
        for (String f : r.changedFiles()) { w.value(f); }
        w.arrayEnd();
        w.key("affectedRequirements"); w.arrayStart();
        for (String f : r.affectedReqs()) { w.value(f); }
        w.arrayEnd();
        w.key("affectedTests"); w.arrayStart();
        for (String f : r.affectedTests()) { w.value(f); }
        w.arrayEnd();
        w.key("summary"); w.arrayStart();
        for (String s : r.summary()) { w.value(s); }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(IMPACT_JSON), w.toPretty() + "\n");
        r.summary().forEach(System.out::println);
    }
}
