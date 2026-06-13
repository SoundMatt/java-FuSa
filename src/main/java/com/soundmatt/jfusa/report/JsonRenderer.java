package com.soundmatt.jfusa.report;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.internal.Json;

import java.time.Instant;

/**
 * JSON check-report renderer — §3.1 common header + §3.2 report extension + §4 findings.
 */
public final class JsonRenderer {

    private JsonRenderer() {}

    public static String render(Report r) {
        var w = new Json.Writer();
        w.objectStart();
        // §3.1 common header
        w.field("schemaVersion", r.specVersion());
        w.field("kind", "check-report");
        w.field("tool", r.toolName());
        w.field("toolVersion", r.toolVersion());
        w.field("language", "java");
        w.field("generatedAt", Instant.ofEpochMilli(r.timestampEpochMs()).toString());
        // §3.2 report extension
        w.field("projectRoot", r.projectRoot());
        w.fieldIfNonBlank("project", r.projectName());
        w.fieldIfNonBlank("standard", r.standard());
        // §4 findings
        w.key("findings"); w.arrayStart();
        for (Finding f : r.result().findings()) {
            w.objectStart();
            w.field("ruleId", f.ruleId());
            w.field("severity", f.severity().name());
            w.field("message", f.message());
            w.key("location"); w.objectStart();
            w.field("file", f.location().file());
            if (f.location().line() > 0)      w.field("line",      f.location().line());
            if (f.location().column() > 0)    w.field("column",    f.location().column());
            if (f.location().endLine() > 0)   w.field("endLine",   f.location().endLine());
            if (f.location().endColumn() > 0) w.field("endColumn", f.location().endColumn());
            w.objectEnd();
            if (f.category() != null) w.field("category", f.category().jsonValue());
            w.fieldIfNonBlank("standard",    f.standard());
            w.fieldIfNonBlank("clause",      f.clause());
            w.fieldIfNonBlank("remediation", f.remediation());
            if (f.disposition() != null && f.disposition() != FuSa.Disposition.open)
                w.field("disposition", f.disposition().name());
            w.fieldIfNonBlank("fingerprint", f.fingerprint());
            w.objectEnd();
        }
        w.arrayEnd();
        // §4 summary — counts by severity regardless of disposition
        long errors   = r.errors().size();
        long warnings = r.warnings().size();
        long infos    = r.infos().size();
        w.key("summary"); w.objectStart();
        w.field("total",    errors + warnings + infos);
        w.field("errors",   errors);
        w.field("warnings", warnings);
        w.field("infos",    infos);
        w.objectEnd();
        if (!r.result().errors().isEmpty()) {
            w.key("error"); w.objectStart();
            w.field("code", "internal");
            w.field("message", String.join("; ", r.result().errors()));
            w.objectEnd();
        }
        w.objectEnd();
        return w.toPretty() + "\n";
    }
}
