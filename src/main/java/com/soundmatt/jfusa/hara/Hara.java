package com.soundmatt.jfusa.hara;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Hazard Analysis and Risk Assessment (HARA) — ISO 26262 Part 3.
 * Manages .fusa-hara.json.
 */
public final class Hara {

    public static final String HARA_FILE = ".fusa-hara.json";

    private Hara() {}

    public record HazardEntry(
            String id, String hazard, String operationalSituation,
            String severity, int s, int e, int c, String asil, String safetyGoal) {}

    /** Derive ASIL from Severity (S), Exposure (E), and Controllability (C) per ISO 26262-3 Table 4. */
    //fusa:req REQ-HARA001
    public static String deriveAsil(int s, int e, int c) {
        // ISO 26262-3:2018 Table 4 — simplified
        if (s == 0) return "QM";
        if (s == 1) {
            if (e <= 2 || c <= 1) return "QM";
            if (c == 2) return e >= 3 ? "QM" : "QM";
            return "QM";
        }
        if (s == 2) {
            if (e <= 1) return "QM";
            if (e == 2) return c <= 2 ? "QM" : "QM";
            if (e == 3) return c <= 1 ? "QM" : (c == 2 ? "A" : "B");
            return c <= 1 ? "A" : (c == 2 ? "B" : "C");
        }
        // s == 3
        if (e <= 1) return c <= 2 ? "QM" : "A";
        if (e == 2) return c <= 1 ? "A" : (c == 2 ? "B" : "C");
        if (e == 3) return c <= 1 ? "B" : (c == 2 ? "C" : "D");
        return c <= 1 ? "C" : (c == 2 ? "D" : "D");
    }

    public static List<HazardEntry> defaults(String project) {
        return List.of(
            new HazardEntry("H-001", "Incorrect safety-critical output", "System operating under load",
                    "S3", 3, 3, 2, "ASIL-C", "SG-001: Safety output must remain within safe bounds"),
            new HazardEntry("H-002", "Loss of safety monitoring function", "Normal operation",
                    "S2", 2, 4, 2, "ASIL-B", "SG-002: Monitoring must be continuously available"),
            new HazardEntry("H-003", "Undetected sensor fault", "Environmental disturbance",
                    "S2", 2, 3, 3, "ASIL-B", "SG-003: Single sensor fault must be detectable")
        );
    }

    public static void init(Path root, String project) throws IOException {
        if (Files.exists(root.resolve(HARA_FILE))) return;
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "hara-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("project", project);
        w.field("standard", "iso26262");
        w.key("hazards"); w.arrayStart();
        for (HazardEntry h : defaults(project)) {
            w.objectStart();
            w.field("id", h.id()); w.field("hazard", h.hazard());
            w.field("operationalSituation", h.operationalSituation());
            w.field("severity", h.s()); w.field("exposure", h.e());
            w.field("controllability", h.c()); w.field("asil", h.asil());
            w.field("safetyGoal", h.safetyGoal());
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(HARA_FILE), w.toPretty() + "\n");
    }

    public static String show(Path root) throws IOException {
        if (!Files.exists(root.resolve(HARA_FILE))) return "No .fusa-hara.json found. Run 'jfusa hara init'\n";
        Map<String, Object> doc = Json.parseObject(Files.readString(root.resolve(HARA_FILE)));
        var sb = new StringBuilder();
        sb.append("HARA — Hazard Analysis and Risk Assessment\n");
        sb.append("=".repeat(60)).append('\n');
        sb.append(String.format("%-8s %-30s %-6s %-6s %-6s %-8s %s\n",
                "ID", "Hazard", "S", "E", "C", "ASIL", "Safety Goal"));
        sb.append("-".repeat(60)).append('\n');
        for (Object item : Json.arr(doc, "hazards")) {
            if (item instanceof Map<?,?> h) {
                @SuppressWarnings("unchecked") var m = (Map<String, Object>) h;
                sb.append(String.format("%-8s %-30s %-6s %-6s %-6s %-8s %s\n",
                        Json.str(m, "id", ""), Json.str(m, "hazard", "").substring(0, Math.min(29, Json.str(m, "hazard", "").length())),
                        Json.str(m, "severity", ""), Json.str(m, "exposure", ""),
                        Json.str(m, "controllability", ""), Json.str(m, "asil", ""),
                        Json.str(m, "safetyGoal", "")));
            }
        }
        return sb.toString();
    }
}
