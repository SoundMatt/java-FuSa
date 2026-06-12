package com.soundmatt.jfusa.report;

import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.internal.Json;

/** SARIF 2.1.0 renderer — GitHub Code Scanning compatible. */
public final class SarifRenderer {

    private SarifRenderer() {}

    public static String render(Report r) {
        var w = new Json.Writer();
        w.objectStart();
        w.field("$schema", "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json");
        w.field("version", "2.1.0");
        w.key("runs"); w.arrayStart();
        w.objectStart();

        // Tool
        w.key("tool"); w.objectStart();
        w.key("driver"); w.objectStart();
        w.field("name", r.toolName());
        w.field("version", r.toolVersion());
        w.field("informationUri", "https://github.com/SoundMatt/java-FuSa");
        w.key("rules"); w.arrayStart();
        // Emit unique rules seen in findings
        r.result().findings().stream().map(Finding::ruleId).distinct().forEach(id -> {
            w.objectStart();
            w.field("id", id);
            w.key("name"); w.value(id);
            w.objectEnd();
        });
        w.arrayEnd();
        w.objectEnd(); // driver
        w.objectEnd(); // tool

        // Results
        w.key("results"); w.arrayStart();
        for (Finding f : r.result().findings()) {
            w.objectStart();
            w.field("ruleId", f.ruleId());
            w.field("level", sarifLevel(f.severity()));
            w.key("message"); w.objectStart();
            w.field("text", f.message() + (f.remediation().isBlank() ? "" : " " + f.remediation()));
            w.objectEnd();
            w.key("locations"); w.arrayStart();
            w.objectStart();
            w.key("physicalLocation"); w.objectStart();
            w.key("artifactLocation"); w.objectStart();
            w.field("uri", f.location().file());
            w.objectEnd();
            if (f.location().line() > 0) {
                w.key("region"); w.objectStart();
                w.field("startLine", f.location().line());
                if (f.location().column() > 0) w.field("startColumn", f.location().column());
                w.objectEnd();
            }
            w.objectEnd(); // physicalLocation
            w.objectEnd(); // location
            w.arrayEnd();
            if (!f.fingerprint().isBlank()) {
                w.key("fingerprints"); w.objectStart();
                w.field("uniqueId/v1", f.fingerprint());
                w.objectEnd();
            }
            // §2.9: category/standard/clause ride in result.properties (SHOULD)
            boolean hasProp = f.category() != null || !f.standard().isBlank() || !f.clause().isBlank();
            if (hasProp) {
                w.key("properties"); w.objectStart();
                if (f.category() != null) w.field("category", f.category().jsonValue());
                if (!f.standard().isBlank()) w.field("standard", f.standard());
                if (!f.clause().isBlank())  w.field("clause", f.clause());
                w.objectEnd();
            }
            w.objectEnd(); // result
        }
        w.arrayEnd(); // results

        w.objectEnd(); // run
        w.arrayEnd(); // runs
        w.objectEnd(); // root
        return w.toPretty() + "\n";
    }

    private static String sarifLevel(Severity s) {
        return switch (s) {
            case ERROR   -> "error";
            case WARNING -> "warning";
            case INFO    -> "note";
        };
    }
}
