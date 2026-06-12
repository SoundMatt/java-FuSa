package com.soundmatt.jfusa.tara;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Threat Analysis and Risk Assessment (TARA) per ISO 21434 Ch. 9.
 * Generates tara.json and tara.md.
 */
public final class Tara {

    public static final String TARA_JSON = "tara.json";
    public static final String TARA_MD   = "tara.md";

    private Tara() {}

    public record ThreatEntry(
            String id, String asset, String threatScenario, String attackVector,
            String attackFeasibility, String impactRating, String riskLevel,
            String cweId, String mitigation) {}

    public static List<ThreatEntry> defaultThreats(String projectName) {
        return List.of(
            new ThreatEntry("T-001", projectName + " build artifacts",
                "Supply chain compromise via malicious dependency",
                "Network", "High", "Critical", "High",
                "CWE-829", "Pin dependency versions; verify checksums (SBOM); use SLSA provenance"),
            new ThreatEntry("T-002", "Configuration files",
                "Credential exposure via hardcoded secrets in source",
                "Local", "Low", "High", "High",
                "CWE-259", "Use environment variables or secrets management; enforce CYBER005/CYBER006"),
            new ThreatEntry("T-003", "Runtime process",
                "Privilege escalation via command injection",
                "Network/Local", "Medium", "Critical", "High",
                "CWE-78", "Input validation; process isolation; least-privilege execution"),
            new ThreatEntry("T-004", "Audit logs",
                "Log tampering to hide malicious activity",
                "Local", "Low", "High", "Medium",
                "CWE-117", "Centralised tamper-evident logging; hash chaining"),
            new ThreatEntry("T-005", "Safety decision outputs",
                "Integrity violation of safety-critical output data",
                "Network", "Medium", "Critical", "High",
                "CWE-345", "Digital signatures; integrity checks on all safety outputs; HMAC-SHA256"),
            new ThreatEntry("T-006", "Memory allocations",
                "Denial of service via resource exhaustion",
                "Network", "Medium", "High", "Medium",
                "CWE-770", "Input size limits; rate limiting; circuit breakers"),
            new ThreatEntry("T-007", "XML/JSON parser",
                "Data injection via malformed input",
                "Network", "Medium", "High", "Medium",
                "CWE-611", "Disable external entities; validate schemas; use safe parsers")
        );
    }

    public static void generate(Path projectRoot, String projectName) throws IOException {
        List<ThreatEntry> threats = defaultThreats(projectName);
        writeJson(projectRoot, threats, projectName);
        writeMarkdown(projectRoot, threats, projectName);
    }

    static void writeJson(Path root, List<ThreatEntry> threats, String project) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-tara-1.0");
        w.field("project", project);
        w.field("standard", "ISO 21434");
        w.field("timestamp", Instant.now().toString());
        w.key("threats"); w.arrayStart();
        for (ThreatEntry t : threats) {
            w.objectStart();
            w.field("id", t.id());
            w.field("asset", t.asset());
            w.field("threatScenario", t.threatScenario());
            w.field("attackVector", t.attackVector());
            w.field("attackFeasibility", t.attackFeasibility());
            w.field("impactRating", t.impactRating());
            w.field("riskLevel", t.riskLevel());
            w.field("cweId", t.cweId());
            w.field("mitigation", t.mitigation());
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(TARA_JSON), w.toPretty() + "\n");
    }

    static void writeMarkdown(Path root, List<ThreatEntry> threats, String project) throws IOException {
        var sb = new StringBuilder();
        sb.append("# Threat Analysis and Risk Assessment (TARA)\n\n");
        sb.append("**Project:** ").append(project).append("  \n");
        sb.append("**Standard:** ISO 21434 Chapter 9  \n");
        sb.append("**Generated:** ").append(Instant.now()).append("\n\n");
        sb.append("## Threat Catalogue\n\n");
        sb.append("| ID | Asset | Threat Scenario | Feasibility | Impact | Risk | CWE | Mitigation |\n");
        sb.append("|---|---|---|---|---|---|---|---|\n");
        for (ThreatEntry t : threats) {
            sb.append("| ").append(t.id()).append(" | ").append(t.asset())
              .append(" | ").append(t.threatScenario())
              .append(" | ").append(t.attackFeasibility())
              .append(" | ").append(t.impactRating())
              .append(" | ").append(t.riskLevel())
              .append(" | ").append(t.cweId())
              .append(" | ").append(t.mitigation()).append(" |\n");
        }
        Files.writeString(root.resolve(TARA_MD), sb.toString());
    }
}
