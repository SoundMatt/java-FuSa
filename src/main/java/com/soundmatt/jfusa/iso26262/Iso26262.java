package com.soundmatt.jfusa.iso26262;

import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** ISO 26262 Part 6 compliance gap report (ASIL A–D). */
public final class Iso26262 {

    public static final String GAP_REPORT = "iso26262-gap-report.json";

    private Iso26262() {}

    public record GapItem(String clause, String title, String status, String notes) {}

    public static List<GapItem> buildGapReport(String asil) {
        return List.of(
            gap("6.4.1",  "Design principles",             "Partially Met", "FUSA rules enforce basic design constraints; full ASIL-" + asil + " review needed"),
            gap("6.4.2",  "Defensive implementation",       "Partially Met", "LINT002/ANA005 enforce error handling; manual review required"),
            gap("6.4.3",  "Code review",                    "Not Met",       "Formal peer review process not automated; use code-review checklist"),
            gap("6.4.4",  "Unit testing",                   "Partially Met", "VERIFY001 checks for test evidence; MC/DC coverage not enforced"),
            gap("6.4.5",  "Integration testing",            "Not Met",       "Integration test framework not configured"),
            gap("6.5.1",  "Software component testing",     "Partially Met", "JUnit coverage measured; coverage goal per ASIL-" + asil + " not enforced"),
            gap("6.5.2",  "Software integration testing",   "Not Met",       "No automated integration test gate"),
            gap("6.7",    "Configuration management",       "Met",           "RELEASE001/002 enforce SBOM + provenance; add git tagging discipline"),
            gap("6.8",    "Change management",              "Partially Met", "diff command tracks introduced findings; no formal change request process"),
            gap("6.9",    "Verification",                   "Partially Met", "jfusa verify produces evidence; formal verification not performed"),
            gap("Part 8", "HARA and safety goals",          "Met",           ".fusa-hara.json present and ASIL derived"),
            gap("Part 9", "Functional safety concept",      "Partially Met", "safety-case.md/json present; formal FSC document not generated")
        );
    }

    static GapItem gap(String clause, String title, String status, String notes) {
        return new GapItem(clause, title, status, notes);
    }

    public static void generate(Path root, String asil) throws IOException {
        List<GapItem> items = buildGapReport(asil);
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-gap-report-1.0");
        w.field("standard", "ISO 26262");
        w.field("asil", "ASIL-" + asil);
        w.field("timestamp", Instant.now().toString());
        w.key("objectives"); w.arrayStart();
        for (GapItem g : items) {
            w.objectStart();
            w.field("clause", g.clause());
            w.field("title", g.title());
            w.field("status", g.status());
            w.field("notes", g.notes());
            w.objectEnd();
        }
        w.arrayEnd();
        long met = items.stream().filter(i -> i.status().equals("Met")).count();
        w.field("totalObjectives", items.size());
        w.field("met", met);
        w.field("partial", items.stream().filter(i -> i.status().equals("Partially Met")).count());
        w.field("notMet", items.stream().filter(i -> i.status().equals("Not Met")).count());
        w.objectEnd();
        Files.writeString(root.resolve(GAP_REPORT), w.toPretty() + "\n");
    }

    public static String renderText(String asil) {
        List<GapItem> items = buildGapReport(asil);
        var sb = new StringBuilder();
        sb.append("ISO 26262 Part 6 Gap Report — ASIL-").append(asil).append("\n");
        sb.append("=".repeat(60)).append('\n');
        sb.append(String.format("%-10s %-35s %-15s %s\n", "Clause", "Title", "Status", "Notes"));
        sb.append("-".repeat(60)).append('\n');
        for (GapItem g : items) {
            sb.append(String.format("%-10s %-35s %-15s %s\n",
                    g.clause(), g.title().substring(0, Math.min(34, g.title().length())),
                    g.status(), g.notes().substring(0, Math.min(40, g.notes().length()))));
        }
        return sb.toString();
    }
}
