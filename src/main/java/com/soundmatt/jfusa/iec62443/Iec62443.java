package com.soundmatt.jfusa.iec62443;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** IEC 62443 industrial cybersecurity compliance — Security Level checks. */
public final class Iec62443 {

    public static final String GAP_REPORT = "iec62443-gap-report.json";

    static {
        Engine.DEFAULT.mustRegister(new RuleIncidentResponsePresent());
    }

    private Iec62443() {}
    public static void activate() {}

    /** §9.3 canonical gap-report for IEC 62443-4-1 at a given Security Level. */
    //fusa:req REQ-IEC62443001
    public static void generate(Path root, String sl) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "gap-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("standard", "iec62443");
        w.field("level", sl);
        record Obj(String id, String title, String clause, String status) {}
        List<Obj> objectives = List.of(
            new Obj("SR-2.1",  "Authorization Enforcement",       "SR 2.1",  "partial"),
            new Obj("SR-3.3",  "Security Functionality Checking",  "SR 3.3",  "partial"),
            new Obj("SR-6.2",  "Continuous Monitoring",            "SR 6.2",  "gap"),
            new Obj("SM-1",    "Security Management Plan",         "§4.1",    "partial"),
            new Obj("SM-7",    "Vulnerability Management",         "§4.7",    "partial")
        );
        int satisfied = 0, partial = 0, gaps = 0;
        w.key("objectives"); w.arrayStart();
        for (Obj o : objectives) {
            w.objectStart();
            w.field("id", o.id());
            w.field("title", o.title());
            w.field("clause", o.clause());
            w.field("status", o.status());
            w.key("evidence"); w.arrayStart(); w.arrayEnd();
            w.key("findings"); w.arrayStart(); w.arrayEnd();
            w.objectEnd();
            if ("satisfied".equals(o.status())) satisfied++;
            else if ("partial".equals(o.status())) partial++;
            else gaps++;
        }
        w.arrayEnd();
        w.key("summary"); w.objectStart();
        w.field("total",     objectives.size());
        w.field("satisfied", satisfied);
        w.field("partial",   partial);
        w.field("gaps",      gaps);
        w.objectEnd();
        w.objectEnd();
        Files.writeString(root.resolve(GAP_REPORT), w.toPretty() + "\n");
    }

    static final class RuleIncidentResponsePresent implements Rule {
        public String id() { return "IEC62443-001"; }
        public String description() { return "INCIDENT-RESPONSE.md must be present (IEC 62443-4-1 SR 6.2)."; }

        //fusa:req REQ-IEC62443002
        public List<Finding> run(Path root, Config cfg) {
            if (!Files.exists(root.resolve("INCIDENT-RESPONSE.md"))) {
                return List.of(Finding.builder("IEC62443-001", Severity.WARNING,
                        "no INCIDENT-RESPONSE.md — IEC 62443-4-1 SR 6.2 requires incident handling process",
                        new FuSa.Location("INCIDENT-RESPONSE.md"))
                        .category(FuSa.Category.security)
                        .standard("IEC 62443-4-1").clause("SR 6.2")
                        .remediation("create INCIDENT-RESPONSE.md with triage, containment, and notification procedures")
                        .build());
            }
            return List.of();
        }
    }
}
