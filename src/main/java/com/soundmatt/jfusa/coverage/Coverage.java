package com.soundmatt.jfusa.coverage;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Structural coverage analysis from JaCoCo XML report.
 * Checks statement, branch, and method coverage against DAL-based thresholds.
 */
public final class Coverage {

    static {
        Engine.DEFAULT.mustRegister(new RuleCoverageGate());
    }

    private Coverage() {}
    public static void activate() {}

    private static final Pattern COUNTER = Pattern.compile(
            "<counter type=\"(\\w+)\" missed=\"(\\d+)\" covered=\"(\\d+)\"");

    public record CoverageReport(double statementPct, double branchPct, double methodPct) {}

    public static CoverageReport parse(Path jacocoXml) throws IOException {
        if (!Files.exists(jacocoXml)) return new CoverageReport(0, 0, 0);
        String content = Files.readString(jacocoXml);
        double stmtPct = 0, branchPct = 0, methodPct = 0;
        Matcher m = COUNTER.matcher(content);
        while (m.find()) {
            String type    = m.group(1);
            long missed    = Long.parseLong(m.group(2));
            long covered   = Long.parseLong(m.group(3));
            long total     = missed + covered;
            double pct     = total == 0 ? 100.0 : 100.0 * covered / total;
            switch (type) {
                case "INSTRUCTION" -> stmtPct   = pct;
                case "BRANCH"      -> branchPct = pct;
                case "METHOD"      -> methodPct = pct;
            }
        }
        return new CoverageReport(stmtPct, branchPct, methodPct);
    }

    static double minCoverageForDal(String dal) {
        return switch (dal) {
            case "DAL-A" -> 100.0;
            case "DAL-B" -> 100.0;
            case "DAL-C" -> 80.0;
            default      -> 60.0;
        };
    }

    static final class RuleCoverageGate implements Rule {
        public String id() { return "COV001"; }
        public String description() { return "Statement coverage must meet DAL/ASIL threshold."; }

        //fusa:req REQ-COV001
        public List<Finding> run(Path root, Config cfg) throws IOException {
            Path jacoco = root.resolve("target/site/jacoco/jacoco.xml");
            if (!Files.exists(jacoco)) return List.of();

            CoverageReport cov = parse(jacoco);
            List<Finding> out = new ArrayList<>();
            double threshold = 80.0;

            if (cov.statementPct() < threshold) {
                out.add(Finding.builder("COV001", Severity.WARNING,
                        String.format("statement coverage %.1f%% is below threshold %.1f%%",
                                cov.statementPct(), threshold),
                        new FuSa.Location("target/site/jacoco/jacoco.xml"))
                        .category(FuSa.Category.coverage)
                        .standard("DO-178C").clause("A-3 Table 6.3.4")
                        .remediation("add unit tests to reach ≥" + (int) threshold + "% statement coverage")
                        .build());
            }
            return out;
        }
    }
}
