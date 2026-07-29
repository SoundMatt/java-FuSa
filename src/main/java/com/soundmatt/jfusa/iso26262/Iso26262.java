package com.soundmatt.jfusa.iso26262;

import com.soundmatt.jfusa.FuSa;
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

    //fusa:req REQ-ISO26262001
    public record GapItem(String clause, String title, String status, String notes) {}

    //fusa:req REQ-ISO26262001
    public static List<GapItem> buildGapReport(String asil) {
        String level = asil.replace("ASIL-", "");
        return List.of(
            gap("6.4.1",  "Design principles",             "Partially Met", "FUSA rules enforce basic design constraints; full ASIL-" + level + " review needed"),
            gap("6.4.2",  "Defensive implementation",       "Partially Met", "LINT002/ANA005 enforce error handling; manual review required"),
            gap("6.4.3",  "Code review",                    "Not Met",       "Formal peer review process not automated; use code-review checklist"),
            gap("6.4.4",  "Unit testing",                   "Partially Met", "VERIFY001 checks for test evidence; MC/DC coverage not enforced"),
            gap("6.4.5",  "Integration testing",            "Not Met",       "Integration test framework not configured"),
            gap("6.5.1",  "Software component testing",     "Partially Met", "JUnit coverage measured; coverage goal per ASIL-" + level + " not enforced"),
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

    private static String canonicalStatus(String s) {
        return switch (s) {
            case "Met"           -> "satisfied";
            case "Partially Met" -> "partial";
            default              -> "gap";
        };
    }

    //fusa:req REQ-ISO26262001
    public static void generate(Path root, String asil) throws IOException {
        List<GapItem> items = buildGapReport(asil);
        var w = new Json.Writer();
        w.objectStart();
        // §3.1 common header
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "gap-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        // §9.3 gap-report body
        w.field("standard", "iso26262");
        w.field("level", "ASIL-" + asil.replace("ASIL-", ""));
        w.key("objectives"); w.arrayStart();
        for (GapItem g : items) {
            w.objectStart();
            w.field("id", g.clause());
            w.field("title", g.title());
            w.field("clause", g.clause());
            w.field("status", canonicalStatus(g.status()));
            w.key("evidence"); w.arrayStart(); w.arrayEnd();
            w.key("findings"); w.arrayStart(); w.arrayEnd();
            w.field("notes", g.notes());
            w.objectEnd();
        }
        w.arrayEnd();
        long satisfied = items.stream().filter(i -> i.status().equals("Met")).count();
        long partial   = items.stream().filter(i -> i.status().equals("Partially Met")).count();
        long gaps      = items.stream().filter(i -> i.status().equals("Not Met")).count();
        w.key("summary"); w.objectStart();
        w.field("total", items.size());
        w.field("satisfied", satisfied);
        w.field("partial", partial);
        w.field("gaps", gaps);
        w.objectEnd();
        w.objectEnd();
        Files.writeString(root.resolve(GAP_REPORT), w.toPretty() + "\n");
    }

    //fusa:req REQ-ISO26262001
    public static String renderText(String asil) {
        List<GapItem> items = buildGapReport(asil);
        var sb = new StringBuilder();
        sb.append("ISO 26262 Part 6 Gap Report — ASIL-").append(asil.replace("ASIL-", "")).append("\n");
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
