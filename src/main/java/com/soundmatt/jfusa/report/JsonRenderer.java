package com.soundmatt.jfusa.report;

import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.internal.Json;

import java.time.Instant;

/** JSON compliance report renderer (x-FuSa §8 schema). */
public final class JsonRenderer {

    private JsonRenderer() {}

    public static String render(Report r) {
        var w = new Json.Writer();
        w.objectStart();
        w.key("tool"); w.objectStart();
        w.field("name", r.toolName());
        w.field("version", r.toolVersion());
        w.field("specVersion", r.specVersion());
        w.objectEnd();
        w.field("project", r.projectName());
        w.field("standard", r.standard());
        w.field("timestamp", Instant.ofEpochMilli(r.timestampEpochMs()).toString());
        w.key("findings"); w.arrayStart();
        for (Finding f : r.result().findings()) {
            w.objectStart();
            w.field("ruleId", f.ruleId());
            w.field("severity", f.severity().name());
            w.field("message", f.message());
            w.key("location"); w.objectStart();
            w.field("file", f.location().file());
            if (f.location().line() > 0)   w.field("line",      f.location().line());
            if (f.location().column() > 0) w.field("column",    f.location().column());
            if (f.location().endLine() > 0)   w.field("endLine",   f.location().endLine());
            if (f.location().endColumn() > 0) w.field("endColumn", f.location().endColumn());
            w.objectEnd();
            if (f.category() != null) w.field("category", f.category().toString());
            w.fieldIfNonBlank("standard",    f.standard());
            w.fieldIfNonBlank("clause",      f.clause());
            w.fieldIfNonBlank("remediation", f.remediation());
            if (f.disposition() != null) w.field("disposition", f.disposition().name());
            w.fieldIfNonBlank("fingerprint", f.fingerprint());
            w.objectEnd();
        }
        w.arrayEnd();
        w.key("summary"); w.objectStart();
        w.field("errors",   r.errors().size());
        w.field("warnings", r.warnings().size());
        w.field("infos",    r.infos().size());
        w.field("status",   r.result().hasErrors() ? "FAIL" : "PASS");
        w.objectEnd();
        if (!r.result().errors().isEmpty()) {
            w.key("executionErrors"); w.arrayStart();
            for (String e : r.result().errors()) w.value(e);
            w.arrayEnd();
        }
        w.objectEnd();
        return w.toPretty() + "\n";
    }
}
