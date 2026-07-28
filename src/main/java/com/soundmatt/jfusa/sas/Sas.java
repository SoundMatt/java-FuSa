package com.soundmatt.jfusa.sas;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.attestation.Attestation;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.qualitybar.QualityBar;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Software Accomplishment Summary — DO-178C §11.20 (x-FuSa spec §9.3).
 * Generates {@code sas.md} (always) and, on request, {@code sas.json}
 * ({@code checklist[]}/{@code summary}/{@code attestation}).
 */
public final class Sas {

    public static final String SAS_MD = "sas.md";
    public static final String SAS_JSON = "sas.json";

    private static final List<String[]> LIFECYCLE_DATA = List.of(
        new String[]{"Plan for Software Aspects of Certification (PSAC)", "11.1",  ".fusa.json"},
        new String[]{"Software Development Plan (SDP)",                   "11.4",  ".fusa.json"},
        new String[]{"Software Requirements Standards",                   "11.6",  ".fusa-reqs.json"},
        new String[]{"Software Design Standards",                         "11.7",  ".fusa.json"},
        new String[]{"Software Code Standards",                           "11.9",  ".fusa.json"},
        new String[]{"Software Requirements Data (HLR)",                  "11.10", ".fusa-reqs.json"},
        new String[]{"Software Design Description (LLR)",                 "11.11", "safety-case.json"},
        new String[]{"Source Code",                                        "11.12", "pom.xml"},
        new String[]{"Executable Object Code",                             "11.13", "target/jfusa.jar"},
        new String[]{"Software Verification Plan",                         "11.5",  ".fusa.json"},
        new String[]{"Software Verification Results",                      "11.14", "qualify-report.json"},
        new String[]{"Software Configuration Management Plan",             "11.3",  ".fusa.json"},
        new String[]{"Software Quality Assurance Plan",                    "11.2",  ".fusa.json"},
        new String[]{"Software Configuration Index (SCI)",                 "11.16", "sci.json"},
        new String[]{"Problem Reports",                                    "11.17", ".fusa-problems.json"},
        new String[]{"Software Life Cycle Environment Configuration",      "11.15", "sbom.json"},
        new String[]{"Additional Considerations",                          "11.21", "CHANGELOG.md"}
    );

    private Sas() {}

    public record ChecklistItem(String item, String clause, boolean present, String evidence) {}

    public record Summary(int total, int present) {}

    public record SasReport(List<ChecklistItem> checklist, Summary summary, Attestation attestation) {}

    //fusa:req REQ-SAS001
    public static SasReport build(Path root) throws IOException {
        List<ChecklistItem> checklist = new ArrayList<>();
        int present = 0;
        for (String[] item : LIFECYCLE_DATA) {
            boolean exists = Files.exists(root.resolve(item[2]));
            if (exists) present++;
            checklist.add(new ChecklistItem(item[0], item[1], exists, item[2]));
        }
        Attestation existing = loadExistingAttestation(root);
        return new SasReport(checklist, new Summary(checklist.size(), present), existing);
    }

    static Attestation loadExistingAttestation(Path root) throws IOException {
        Path f = root.resolve(SAS_JSON);
        if (!Files.exists(f)) return null;
        try {
            return Attestation.fromJson(Json.parseObject(Files.readString(f)));
        } catch (Json.JsonParseException e) {
            return null;
        }
    }

    /** {@code checklist[].item} descriptions are free text subject to §1.6.1's content-quality baseline. */
    //fusa:req REQ-SAS005
    public static List<QualityBar.Field> qualityBarFields(List<ChecklistItem> checklist) {
        List<QualityBar.Field> fields = new ArrayList<>();
        for (int i = 0; i < checklist.size(); i++) {
            fields.add(new QualityBar.Field("item-" + (i + 1), "item", checklist.get(i).item()));
        }
        return fields;
    }

    //fusa:req REQ-SAS005
    public static List<Object> substantiveContent(List<ChecklistItem> checklist) {
        List<Object> out = new ArrayList<>();
        for (ChecklistItem c : checklist) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("item", c.item());
            m.put("clause", c.clause());
            m.put("present", c.present());
            m.put("evidence", c.evidence());
            out.add(m);
        }
        return out;
    }

    //fusa:req REQ-SAS002
    public static void writeJson(Path root, SasReport report, String outputFile) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "sas");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.key("checklist"); w.rawValue(substantiveContent(report.checklist()));
        w.key("summary"); w.objectStart();
        w.field("total", report.summary().total());
        w.field("present", report.summary().present());
        w.objectEnd();
        if (report.attestation() != null) report.attestation().writeJson(w);
        w.objectEnd();
        String path = (outputFile == null || outputFile.isBlank()) ? SAS_JSON : outputFile;
        Files.writeString(root.resolve(path), w.toPretty() + "\n");
    }

    //fusa:req REQ-SAS003
    public static void writeMarkdown(Path root, SasReport report) throws IOException {
        var sb = new StringBuilder();
        sb.append("# Software Accomplishment Summary\n\n");
        sb.append("**Standard:** DO-178C §11.20  \n");
        sb.append("**Tool:** jfusa v").append(FuSa.VERSION).append("  \n");
        sb.append("**Generated:** ").append(Instant.now()).append("\n\n");
        sb.append("## Lifecycle Data Items\n\n");
        sb.append("| Lifecycle Data Item | §11 Ref | File | Status |\n");
        sb.append("|---|---|---|---|\n");
        for (ChecklistItem c : report.checklist()) {
            sb.append("| ").append(c.item()).append(" | ").append(c.clause()).append(" | `")
              .append(c.evidence()).append("` | ").append(c.present() ? "Present" : "Missing").append(" |\n");
        }
        sb.append("\n## Summary\n\n");
        sb.append(String.format("- Total lifecycle data items: **%d**%n", report.summary().total()));
        sb.append(String.format("- Present: **%d** (%.0f%%)%n", report.summary().present(),
                100.0 * report.summary().present() / report.summary().total()));
        sb.append(String.format("- Missing: **%d**%n", report.summary().total() - report.summary().present()));
        sb.append("\n## Certification Basis\n\n");
        sb.append("This SAS was generated by jfusa v").append(FuSa.VERSION)
          .append(" in accordance with DO-178C, DAL per project configuration.\n");
        sb.append("All evidence artifacts can be bundled via `jfusa audit-pack`.\n");
        Files.writeString(root.resolve(SAS_MD), sb.toString());
    }

    /** Back-compat convenience: builds the report and writes only {@code sas.md} (original behaviour). */
    //fusa:req REQ-SAS001
    public static void generate(Path root) throws IOException {
        SasReport report = build(root);
        writeMarkdown(root, report);
        System.out.println("SAS generated: " + SAS_MD + " (" + report.summary().present() + "/"
                + report.summary().total() + " items present)");
    }
}
