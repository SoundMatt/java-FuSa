package com.soundmatt.jfusa.unece;

import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** UN R.155 Annex 5 — threat-category coverage assessment (TC-1 through TC-9). */
public final class Unece {

    public static final String GAP_REPORT = "unece-gap-report.json";

    private Unece() {}

    public record ThreatCategory(String id, String title, String status, String coverage) {}

    public static List<ThreatCategory> threatCategories() {
        return List.of(
            tc("TC-1", "Threats to vehicle back-end servers",    "Partially Met", "CYBER001-014 cover injection, auth, XXE"),
            tc("TC-2", "Threats to vehicles communication channels", "Partially Met", "CYBER008/009 cover crypto; TLS not enforced"),
            tc("TC-3", "Threats to vehicle update procedures",   "Met",           "SBOM + provenance + SLSA rules"),
            tc("TC-4", "Threats to unintended human actions",    "Partially Met", "Input validation rules CYBER001-004"),
            tc("TC-5", "Threats to external connections",        "Partially Met", "CYBER013 (SSRF), CYBER011 (XXE)"),
            tc("TC-6", "Threats to data",                        "Partially Met", "CYBER005/006 hardcoded creds; CYBER017 CSRF"),
            tc("TC-7", "Threats to vehicle supply chain",        "Met",           "SBOM + provenance + SLSA rules"),
            tc("TC-8", "Threats to vehicle maintenance/diagnosis","Partially Met", "No diagnostic interface-specific rules"),
            tc("TC-9", "Cryptographic vulnerabilities",          "Met",           "CYBER007/008/009 cover weak crypto/RNG/hash")
        );
    }

    static ThreatCategory tc(String id, String t, String s, String c) { return new ThreatCategory(id, t, s, c); }

    public static void generate(Path root) throws IOException {
        List<ThreatCategory> cats = threatCategories();
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-gap-report-1.0");
        w.field("standard", "UN R.155 Annex 5");
        w.field("timestamp", Instant.now().toString());
        w.key("threatCategories"); w.arrayStart();
        for (ThreatCategory tc : cats) {
            w.objectStart();
            w.field("id", tc.id()); w.field("title", tc.title());
            w.field("status", tc.status()); w.field("coverage", tc.coverage());
            w.objectEnd();
        }
        w.arrayEnd();
        long met = cats.stream().filter(c -> c.status().equals("Met")).count();
        w.field("met", met); w.field("total", cats.size());
        w.objectEnd();
        Files.writeString(root.resolve(GAP_REPORT), w.toPretty() + "\n");
    }

    public static String renderText() {
        var sb = new StringBuilder();
        sb.append("UN R.155 Annex 5 Threat Category Coverage\n");
        sb.append("=".repeat(60)).append('\n');
        for (ThreatCategory tc : threatCategories()) {
            sb.append(String.format("%-6s %-40s [%s]\n", tc.id(),
                    tc.title().substring(0, Math.min(39, tc.title().length())), tc.status()));
            sb.append("         ").append(tc.coverage()).append('\n');
        }
        return sb.toString();
    }
}
