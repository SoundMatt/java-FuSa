package com.soundmatt.jfusa.safetycase;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * Safety case assembly — evidence collection, GSN diagram, and compliance mapping.
 */
public final class SafetyCase {

    public static final String SAFETY_CASE_MD   = "safety-case.md";
    public static final String SAFETY_CASE_JSON = "safety-case.json";
    public static final String SAFETY_CASE_MERMAID = "safety-case.mermaid";

    private SafetyCase() {}

    public static void generate(Path root, Config cfg) throws IOException {
        String project = cfg != null ? cfg.project().name() : "unknown";
        String standard = cfg != null ? cfg.project().standard().name() : "generic";
        writeJson(root, project, standard);
        writeMarkdown(root, project, standard);
        writeMermaid(root, project);
    }

    static void writeJson(Path root, String project, String standard) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-safety-case-1.0");
        w.field("project", project);
        w.field("standard", standard);
        w.field("timestamp", Instant.now().toString());
        w.key("goals"); w.arrayStart();
        for (String g : List.of(
                "G-001: The system is acceptably safe for its intended use",
                "G-002: All safety requirements are implemented and verified",
                "G-003: All identified hazards are mitigated to an acceptable risk level",
                "G-004: The development process is compliant with " + standard)) {
            w.value(g);
        }
        w.arrayEnd();
        w.key("evidence"); w.arrayStart();
        for (String e : List.of(
                "qualify-report.json", "sbom.json", "provenance.json",
                ".fusa-evidence.json", "tara.json", "fmea.json",
                ".fusa-hara.json", ".fusa-reqs.json")) {
            w.objectStart();
            w.field("artifact", e);
            w.field("present", Files.exists(root.resolve(e)));
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(SAFETY_CASE_JSON), w.toPretty() + "\n");
    }

    static void writeMarkdown(Path root, String project, String standard) throws IOException {
        var sb = new StringBuilder();
        sb.append("# Safety Case — ").append(project).append("\n\n");
        sb.append("**Standard:** ").append(standard).append("  \n");
        sb.append("**Generated:** ").append(Instant.now()).append("\n\n");
        sb.append("## Top-Level Goal\n\n");
        sb.append("**G-001:** The ").append(project)
          .append(" system is acceptably safe for its intended use context.\n\n");
        sb.append("## Strategy\n\n");
        sb.append("**S-001:** Argument over compliance with ").append(standard)
          .append(" and supporting evidence.\n\n");
        sb.append("## Sub-Goals\n\n");
        sb.append("| ID | Goal | Evidence Artifact |\n");
        sb.append("|---|---|---|\n");
        sb.append("| G-002 | All safety requirements implemented and tested | `.fusa-reqs.json`, `.fusa-evidence.json` |\n");
        sb.append("| G-003 | Hazards identified and mitigated | `.fusa-hara.json`, `tara.json` |\n");
        sb.append("| G-004 | Process compliance | `qualify-report.json`, `sbom.json` |\n");
        sb.append("| G-005 | Cybersecurity risks addressed | `tara.json`, `SECURITY.md` |\n\n");
        sb.append("## Evidence Summary\n\n");
        sb.append("| Artifact | Status |\n|---|---|\n");
        for (String art : List.of("qualify-report.json", "sbom.json", "provenance.json",
                ".fusa-evidence.json", "tara.json", "fmea.json", ".fusa-hara.json")) {
            String status = Files.exists(root.resolve(art)) ? "✓ Present" : "✗ Missing";
            sb.append("| `").append(art).append("` | ").append(status).append(" |\n");
        }
        Files.writeString(root.resolve(SAFETY_CASE_MD), sb.toString());
    }

    static void writeMermaid(Path root, String project) throws IOException {
        String content = """
                graph TD
                    G001["G-001: %s is acceptably safe"]
                    S001["S-001: Argument over %s compliance + evidence"]
                    G002["G-002: Requirements implemented & tested"]
                    G003["G-003: Hazards identified & mitigated"]
                    G004["G-004: Process compliance"]
                    G005["G-005: Cyber risks addressed"]
                    E001["E: .fusa-reqs.json + .fusa-evidence.json"]
                    E002["E: .fusa-hara.json + tara.json"]
                    E003["E: qualify-report.json + sbom.json"]
                    E004["E: tara.json + SECURITY.md"]
                    G001 --> S001
                    S001 --> G002
                    S001 --> G003
                    S001 --> G004
                    S001 --> G005
                    G002 --> E001
                    G003 --> E002
                    G004 --> E003
                    G005 --> E004
                """.formatted(project, project);
        Files.writeString(root.resolve(SAFETY_CASE_MERMAID), content);
    }
}
