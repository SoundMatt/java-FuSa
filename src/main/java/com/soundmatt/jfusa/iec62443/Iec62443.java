package com.soundmatt.jfusa.iec62443;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** IEC 62443 industrial cybersecurity compliance — Security Level checks. */
public final class Iec62443 {

    static {
        Engine.DEFAULT.mustRegister(new RuleIncidentResponsePresent());
    }

    private Iec62443() {}
    public static void activate() {}

    static final class RuleIncidentResponsePresent implements Rule {
        public String id() { return "IEC62443-001"; }
        public String description() { return "INCIDENT-RESPONSE.md must be present (IEC 62443-4-1 SR 6.2)."; }

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
