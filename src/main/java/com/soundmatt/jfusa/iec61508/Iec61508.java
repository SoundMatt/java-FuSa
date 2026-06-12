package com.soundmatt.jfusa.iec61508;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** IEC 61508 Parts 1–3 compliance gap report (SIL 1–4). */
public final class Iec61508 {

    public static final String GAP_REPORT = "iec61508-gap-report.json";

    private Iec61508() {}

    public record GapItem(String clause, String title, String sil, String status, String notes) {}

    public static List<GapItem> buildGapReport(String sil) {
        return List.of(
            gap("7.4.2",  "Structured programming",      sil, "Met",           "Java enforces structured programming; LINT rules prevent unsafe idioms"),
            gap("7.4.3",  "Defensive programming",       sil, "Partially Met", "ANA001-006 detect common defects; manual code review still required"),
            gap("7.4.4",  "Failure assertion programming",sil,"Partially Met", "SafeStateGuard implements assertions; not all paths covered"),
            gap("7.4.6",  "Dynamic data structures",     sil, "Partially Met", "LINT004 flags unbounded mutable collections"),
            gap("7.4.7",  "No dynamic objects",          sil, intWarning(sil), dynamicNote(sil)),
            gap("7.4.10", "Exception handling",          sil, "Partially Met", "ANA005 flags empty catch; comprehensive exception strategy needed"),
            gap("7.4.11", "Concurrency",                 sil, "Partially Met", "ANA003/004 detect basic concurrency issues; formal model not enforced"),
            gap("7.8",    "Tool confidence level",       sil, "Met",           "qualify-report.json provides tool confidence evidence"),
            gap("7.9",    "Proven in use",               sil, "Not Met",       "No operational history data collected"),
            gap("Part 1 §8.2", "Functional safety management", sil, "Partially Met", "safety-case.md provides structure; formal FSM plan not generated")
        );
    }

    static GapItem gap(String c, String t, String sil, String s, String n) { return new GapItem(c, t, sil, s, n); }

    private static String canonicalStatus(String s) {
        return switch (s) {
            case "Met"           -> "satisfied";
            case "Partially Met", "Warning" -> "partial";
            default              -> "gap";
        };
    }

    static String intWarning(String sil) {
        return switch (sil) {
            case "SIL-3", "SIL-4" -> "Warning";
            default -> "Met";
        };
    }

    static String dynamicNote(String sil) {
        return switch (sil) {
            case "SIL-3", "SIL-4" -> "SIL-" + sil.replace("SIL-", "") + " recommends avoiding dynamic memory; Java GC is unavoidable";
            default -> "Acceptable for SIL-" + sil.replace("SIL-", "") + " with GC pause analysis";
        };
    }

    public static void generate(Path root, String sil) throws IOException {
        List<GapItem> items = buildGapReport(sil);
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "gap-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("standard", "iec61508");
        w.field("level", "SIL-" + sil.replace("SIL-", ""));
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
        long sat  = items.stream().filter(i -> i.status().equals("Met")).count();
        long part = items.stream().filter(i -> i.status().equals("Partially Met")).count();
        long gap  = items.size() - sat - part;
        w.key("summary"); w.objectStart();
        w.field("total", items.size());
        w.field("satisfied", sat);
        w.field("partial", part);
        w.field("gaps", gap);
        w.objectEnd();
        w.objectEnd();
        Files.writeString(root.resolve(GAP_REPORT), w.toPretty() + "\n");
    }

    public static String renderText(String sil) {
        var sb = new StringBuilder();
        sb.append("IEC 61508 Gap Report — ").append(sil).append('\n');
        sb.append("=".repeat(60)).append('\n');
        for (GapItem g : buildGapReport(sil)) {
            sb.append(String.format("%-12s %-38s %s%n", g.clause(), g.title(), g.status()));
        }
        return sb.toString();
    }
}
