package com.soundmatt.jfusa.do178;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** DO-178C Annex A gap report (DAL A–D). */
public final class Do178 {

    public static final String GAP_REPORT = "do178-gap-report.json";

    private Do178() {}

    public record TableObjective(String table, String objective, String description, String status, String notes) {}

    public static List<TableObjective> buildGapReport(String dal) {
        var items = new ArrayList<TableObjective>();
        // Table A-1: Software Planning Process
        items.add(obj("A-1", "1", "Software planning process",           "Met",           "CLAUDE.md + Makefile define build process"));
        items.add(obj("A-1", "2", "Software development standards",      "Partially Met", "LINT/ANA rules enforce standards; formal SDP not generated"));
        // Table A-2: Software Development Process
        items.add(obj("A-2", "1", "High-level requirements",             "Partially Met", ".fusa-reqs.json captures requirements"));
        items.add(obj("A-2", "2", "Software architecture",               "Partially Met", "boundary.mermaid generated; formal architecture document needed"));
        items.add(obj("A-2", "3", "Low-level requirements",              "Not Met",       "Detailed design docs not automatically generated"));
        items.add(obj("A-2", "4", "Source code",                        "Met",           "Source code under version control"));
        // Table A-3: Verification Process
        items.add(obj("A-3", "1", "Software reviews",                   "Partially Met", "jfusa check enforces review gate; formal peer review checklist needed"));
        items.add(obj("A-3", "2", "Software testing",                   "Partially Met", "JUnit tests present; MC/DC coverage requires DAL-A/B"));
        items.add(obj("A-3", "3", "Test coverage — statement",          dalCovStatus(dal, "stmt"), dalCovNote(dal, "stmt")));
        items.add(obj("A-3", "4", "Test coverage — decision",           dalCovStatus(dal, "dec"),  dalCovNote(dal, "dec")));
        items.add(obj("A-3", "5", "Test coverage — MC/DC",              dalCovStatus(dal, "mcdc"), dalCovNote(dal, "mcdc")));
        // Table A-7: Software Configuration Management
        items.add(obj("A-7", "1", "Configuration identification",        "Met",           "sci command generates Software Configuration Index"));
        items.add(obj("A-7", "2", "Baseline",                            "Partially Met", "SBOM and provenance generated; formal baseline process needed"));
        items.add(obj("A-7", "3", "Problem reporting",                   "Met",           "jfusa pr manages problem report log"));
        // Table A-9: Software Quality Assurance
        items.add(obj("A-9", "1", "Software quality assurance process",  "Partially Met", "jfusa check + qualify enforce QA gate"));
        items.add(obj("A-9", "2", "Compliance",                          "Partially Met", "This gap report; formal compliance matrix not complete"));
        // Table A-10: Certification liaison
        items.add(obj("A-10", "1", "Compliance substantiation",          "Partially Met", "qualify-report.json provides tool evidence"));
        items.add(obj("A-11", "1", "Software accomplishment summary",    "Met",           "jfusa sas generates SAS document"));
        return items;
    }

    static TableObjective obj(String t, String n, String d, String s, String notes) {
        return new TableObjective(t, n, d, s, notes);
    }

    private static String canonicalStatus(String s) {
        return switch (s) {
            case "Met"           -> "satisfied";
            case "Partially Met" -> "partial";
            default              -> "gap";
        };
    }

    static String dalCovStatus(String dal, String type) {
        return switch (dal + ":" + type) {
            case "DAL-A:stmt", "DAL-B:stmt", "DAL-C:stmt" -> "Required";
            case "DAL-A:dec",  "DAL-B:dec"                -> "Required";
            case "DAL-A:mcdc"                              -> "Required";
            default -> "Not Required";
        };
    }

    static String dalCovNote(String dal, String type) {
        return switch (dal + ":" + type) {
            case "DAL-A:mcdc" -> "MC/DC required for DAL-A — JaCoCo reports branch; MC/DC requires dedicated tooling";
            case "DAL-A:dec", "DAL-B:dec" -> "Decision coverage required — configure JaCoCo branch goal ≥100%";
            default -> "Not required for " + dal;
        };
    }

    public static void generate(Path root, String dal) throws IOException {
        List<TableObjective> items = buildGapReport(dal);
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "gap-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("standard", "do178c");
        w.field("level", "DAL-" + dal.replace("DAL-", ""));
        w.key("objectives"); w.arrayStart();
        for (TableObjective o : items) {
            w.objectStart();
            w.field("id", o.table() + "/" + o.objective());
            w.field("title", o.description());
            w.field("clause", o.table());
            w.field("status", canonicalStatus(o.status()));
            w.key("evidence"); w.arrayStart(); w.arrayEnd();
            w.key("findings"); w.arrayStart(); w.arrayEnd();
            w.field("notes", o.notes());
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

    public static String renderText(String dal) {
        var sb = new StringBuilder();
        sb.append("DO-178C Gap Report — ").append(dal).append('\n');
        sb.append("=".repeat(60)).append('\n');
        for (TableObjective o : buildGapReport(dal)) {
            sb.append(String.format("Table %-5s #%-3s %-38s %s%n",
                    o.table(), o.objective(), o.description(), o.status()));
        }
        return sb.toString();
    }
}
