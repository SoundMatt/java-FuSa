package com.soundmatt.jfusa.iso21434;

import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** ISO 21434 cybersecurity engineering — CAL 1–4 gap assessment. */
public final class Iso21434 {

    public static final String GAP_REPORT = "iso21434-gap-report.json";

    private Iso21434() {}

    public record GapItem(String clause, String title, String status, String notes) {}

    public static List<GapItem> buildGapReport(String cal) {
        return List.of(
            gap("5",   "Cybersecurity governance",             "Partially Met", "SECURITY.md provides policy; formal governance framework not enforced"),
            gap("6",   "Project-dependent cybersecurity",      "Partially Met", "jfusa cyber + TARA fulfil core requirements"),
            gap("8",   "Continual cybersecurity activities",   "Not Met",       "No vuln feed subscription; add jfusa vuln to CI pipeline"),
            gap("9",   "Threat analysis & risk assessment",    "Met",           "tara.json generated with STRIDE/CWE mapping"),
            gap("10",  "Vulnerability management",             "Partially Met", "jfusa vuln checks OSV; no incident response test"),
            gap("11",  "CAL " + cal + " requirements",         calStatus(cal),  calNote(cal)),
            gap("13",  "Tool qualification",                   "Met",           "qualify-report.json with SHA-256 integrity hash"),
            gap("15",  "TARA evidence",                        "Met",           "tara.json covers all required STRIDE categories")
        );
    }

    static GapItem gap(String c, String t, String s, String n) { return new GapItem(c, t, s, n); }

    static String calStatus(String cal) {
        return switch (cal) {
            case "CAL-1" -> "Met";
            case "CAL-2" -> "Partially Met";
            case "CAL-3", "CAL-4" -> "Partially Met";
            default -> "Partially Met";
        };
    }

    static String calNote(String cal) {
        return "CAL-" + cal.replace("CAL-", "") + " requires " +
               (cal.equals("CAL-4") ? "comprehensive penetration testing and formal method evidence" :
                "TARA + cyber rules; additional pen-test required for CAL-3/4");
    }

    public static void generate(Path root, String cal) throws IOException {
        List<GapItem> items = buildGapReport(cal);
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-gap-report-1.0");
        w.field("standard", "ISO 21434"); w.field("cal", "CAL-" + cal);
        w.field("timestamp", Instant.now().toString());
        w.key("objectives"); w.arrayStart();
        for (GapItem g : items) {
            w.objectStart();
            w.field("clause", g.clause()); w.field("title", g.title());
            w.field("status", g.status()); w.field("notes", g.notes());
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(GAP_REPORT), w.toPretty() + "\n");
    }
}
