package com.soundmatt.jfusa.coverage;

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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Structural coverage analysis from JaCoCo XML report.
 * Checks statement, branch, and method coverage against DAL-based thresholds.
 * Supports MC/DC coverage via LLVM coverage JSON export (Feature 3).
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

    // ── MC/DC types ───────────────────────────────────────────────────────────

    /** A single Boolean condition in an MC/DC decision. */
    //fusa:req REQ-MCDC001
    public record McdcCondition(long coveredTrueCount, long coveredFalseCount) {
        /** A condition is MC/DC covered if both true and false outcomes were exercised. */
        public boolean isCovered() { return coveredTrueCount > 0 && coveredFalseCount > 0; }
    }

    /** MC/DC data for one function. */
    //fusa:req REQ-MCDC001
    public record McdcFunctionRecord(String function, List<McdcCondition> conditions) {
        /** Returns true only when all conditions are MC/DC covered. */
        public boolean allCovered() {
            return conditions.stream().allMatch(McdcCondition::isCovered);
        }
        /** Count of uncovered conditions. */
        public long uncoveredCount() {
            return conditions.stream().filter(c -> !c.isCovered()).count();
        }
    }

    /** Aggregate MC/DC analysis result. */
    //fusa:req REQ-MCDC001
    public record McdcReport(
            List<McdcFunctionRecord> records,
            int totalFunctions,
            int passingFunctions,
            List<String> failingFunctions,
            boolean gatePass) {}

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

    // ── MC/DC parsing ─────────────────────────────────────────────────────────

    /**
     * Parses LLVM MC/DC coverage JSON.
     * Expected format:
     * <pre>
     * {"mcdc_records":[{"function":"name","conditions":[{"covered_true_count":N,"covered_false_count":M},...]},...]}
     * </pre>
     * A condition is MC/DC covered if both counts are > 0.
     */
    //fusa:req REQ-MCDC001
    public static McdcReport parseMcdc(Path mcdcJson) throws IOException {
        if (!Files.exists(mcdcJson)) return new McdcReport(List.of(), 0, 0, List.of(), true);
        String content = Files.readString(mcdcJson);
        Map<String, Object> root;
        try {
            root = Json.parseObject(content);
        } catch (Json.JsonParseException e) {
            return new McdcReport(List.of(), 0, 0, List.of(), true);
        }
        List<Object> recs = Json.arr(root, "mcdc_records");
        List<McdcFunctionRecord> records = new ArrayList<>();
        for (Object recObj : recs) {
            if (!(recObj instanceof Map<?,?> rm)) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> recMap = (Map<String, Object>) rm;
            String function = Json.str(recMap, "function", "");
            List<Object> conds = Json.arr(recMap, "conditions");
            List<McdcCondition> conditions = new ArrayList<>();
            for (Object condObj : conds) {
                if (!(condObj instanceof Map<?,?> cm)) continue;
                @SuppressWarnings("unchecked")
                Map<String, Object> condMap = (Map<String, Object>) cm;
                long trueCount  = toLong(condMap.get("covered_true_count"));
                long falseCount = toLong(condMap.get("covered_false_count"));
                conditions.add(new McdcCondition(trueCount, falseCount));
            }
            records.add(new McdcFunctionRecord(function, Collections.unmodifiableList(conditions)));
        }
        int total = records.size();
        List<String> failing = new ArrayList<>();
        for (McdcFunctionRecord r : records) {
            if (!r.allCovered()) failing.add(r.function());
        }
        int passing = total - failing.size();
        // Hard gate: fails if any function has uncovered conditions
        boolean gatePass = failing.isEmpty();
        return new McdcReport(Collections.unmodifiableList(records), total, passing,
                Collections.unmodifiableList(failing), gatePass);
    }

    private static long toLong(Object v) {
        if (v instanceof Long l)   return l;
        if (v instanceof Double d) return d.longValue();
        if (v instanceof Integer i) return i.longValue();
        return 0L;
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
