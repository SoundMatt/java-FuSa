package com.soundmatt.jfusa.qualitybar;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.attestation.Attestation;
import com.soundmatt.jfusa.disposition.Disposition;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;

/**
 * x-FuSa spec §1.6.1 detection heuristics — a cross-cutting content-quality
 * baseline shared by every generated evidence artifact with free-text
 * qualitative fields ({@code fmea.json}, {@code .fusa-hara.json},
 * {@code tara.json}, {@code safety-case.*}, {@code sas.*}).
 *
 * <p><b>Rule A / {@code FUSA-STUB001}</b> — literal placeholder/template text.
 * Always an {@code ERROR}; suppressible only via a per-finding disposition
 * (§1.2.3/§4.1), never via attestation.
 *
 * <p><b>Rule B / {@code FUSA-STUB002}</b> — a single hardcoded qualitative
 * string reused across (almost) every entry. A {@code WARNING} by default;
 * suppressible by a non-stale, independent {@code attestation} (§1.6.2).
 */
public final class QualityBar {

    public static final String STUB001 = "FUSA-STUB001";
    public static final String STUB002 = "FUSA-STUB002";

    /** Bracket-wrapped instructional text, e.g. {@code "[describe asset]"}. */
    private static final Pattern BRACKET_PLACEHOLDER = Pattern.compile("\\[[A-Za-z][^\\]]*]");

    /** Case-insensitive deny-list substrings (§1.6.1 rule A). */
    private static final String[] DENYLIST = {
            "replace with", "example hazard", "tbd", "lorem ipsum", "fill in"
    };

    /** Minimum entry count before rule B's distinct-value-ratio check applies (§1.6.1 rule B). */
    public static final int RULE_B_MIN_ENTRIES = 10;

    /** Ratio below which a qualitative field is flagged as a blanket fallback. */
    public static final double RULE_B_RATIO_THRESHOLD = 0.1;

    private QualityBar() {}

    /** One qualitative (entry id, field name, value) tuple to scan. */
    public record Field(String entryId, String fieldName, String value) {}

    // ── Rule A — placeholder text (MUST, always ERROR) ───────────────────────

    //fusa:req REQ-QB001
    public static List<FuSa.Finding> scanPlaceholders(String artifactFile, List<Field> fields) {
        List<FuSa.Finding> out = new ArrayList<>();
        for (Field f : fields) {
            if (f.value() == null) continue;
            String reason = matchDenylist(f.value());
            if (reason != null) {
                out.add(FuSa.Finding.builder(STUB001, FuSa.Severity.ERROR,
                                "placeholder/template text in " + f.entryId() + "." + f.fieldName()
                                        + " (" + reason + ")",
                                new FuSa.Location(artifactFile))
                        .category(FuSa.Category.safety)
                        .remediation("replace the placeholder text with project-specific content, "
                                + "or leave the section empty rather than shipping a dummy row")
                        .build());
            }
        }
        return out;
    }

    private static String matchDenylist(String value) {
        if (BRACKET_PLACEHOLDER.matcher(value).find()) return "bracketed instructional text";
        String lower = value.toLowerCase(Locale.ROOT);
        for (String d : DENYLIST) {
            if (lower.contains(d)) return "matches deny-list phrase \"" + d + "\"";
        }
        return null;
    }

    // ── Rule B — blanket qualitative fallback (SHOULD, WARNING by default) ───

    //fusa:req REQ-QB002
    public static List<FuSa.Finding> scanBlanketFallback(String artifactFile, List<Field> fields) {
        List<FuSa.Finding> out = new ArrayList<>();
        Map<String, List<String>> byField = new LinkedHashMap<>();
        for (Field f : fields) {
            byField.computeIfAbsent(f.fieldName(), k -> new ArrayList<>())
                    .add(f.value() == null ? "" : f.value());
        }
        for (var e : byField.entrySet()) {
            List<String> values = e.getValue();
            if (values.size() < RULE_B_MIN_ENTRIES) continue;
            long distinct = values.stream().distinct().count();
            double ratio = (double) distinct / values.size();
            if (ratio < RULE_B_RATIO_THRESHOLD) {
                out.add(FuSa.Finding.builder(STUB002, FuSa.Severity.WARNING,
                                String.format(Locale.ROOT,
                                        "field \"%s\" has only %d distinct value(s) across %d entries "
                                                + "(ratio %.3f < %.1f) — looks like one hardcoded string reused "
                                                + "regardless of the underlying item",
                                        e.getKey(), distinct, values.size(), ratio, RULE_B_RATIO_THRESHOLD),
                                new FuSa.Location(artifactFile))
                        .category(FuSa.Category.safety)
                        .remediation("vary this field with the entry's actual signature/behaviour, "
                                + "or add a reviewed attestation (§1.6.2) if the similarity is genuine")
                        .build());
            }
        }
        return out;
    }

    /** Convenience: distinct-value ratio for one field's values, for callers that want the raw number. */
    //fusa:req REQ-QB002
    public static double distinctValueRatio(List<String> values) {
        if (values.isEmpty()) return 1.0;
        long distinct = values.stream().distinct().count();
        return (double) distinct / values.size();
    }

    // ── Disposition suppression (Rule A only — never attestation) ────────────

    /**
     * Rule A is suppressible only via a per-finding disposition recorded in
     * {@code .fusa-dispositions.json} (§1.2.3/§4.1) — never via §1.6.2's
     * artifact-level attestation, because no attestation can make literal
     * placeholder text real. An {@code "accepted"}/{@code "deferred"} entry
     * matching this rule id and artifact file suppresses the gate;
     * {@code "rejected"} (a denied waiver) does not.
     */
    //fusa:req REQ-QB003
    public static boolean isDispositioned(Path root, String ruleId, String artifactFile) throws IOException {
        for (Disposition.Entry e : Disposition.load(root)) {
            if (!e.ruleId().equals(ruleId) || !e.file().equals(artifactFile)) continue;
            String action = e.action() == null ? "" : e.action().toLowerCase(Locale.ROOT);
            if (action.equals("accepted") || action.equals("deferred")) return true;
        }
        return false;
    }

    // ── Combined evaluation — used identically by every artifact command ────

    /**
     * @param findings              every Rule A/B finding, with disposition set when suppressed
     * @param hasBlockingError      an unsuppressed Rule A finding — always gates
     * @param hasUnsuppressedWarning a Rule B finding not covered by a valid attestation — only
     *                              gates when the caller is running with {@code --strict}/
     *                              {@code --require-attestation}
     */
    public record Result(List<FuSa.Finding> findings, boolean hasBlockingError, boolean hasUnsuppressedWarning) {}

    /**
     * Runs both detection rules over {@code fields}, applies disposition suppression to Rule A
     * and attestation suppression to Rule B, and returns the combined, gate-ready result.
     */
    //fusa:req REQ-QB004
    public static Result evaluate(Path root, String artifactFile, List<Field> fields,
                                   Attestation attestation, Object substantiveContent) throws IOException {
        List<FuSa.Finding> findings = new ArrayList<>();
        boolean blocking = false;
        for (FuSa.Finding f : scanPlaceholders(artifactFile, fields)) {
            boolean suppressed = isDispositioned(root, STUB001, artifactFile);
            findings.add(suppressed ? withDisposition(f, FuSa.Disposition.accepted) : f);
            if (!suppressed) blocking = true;
        }
        boolean ruleBSuppressed = attestation != null && attestation.suppressesRuleB(substantiveContent);
        boolean warnUnsuppressed = false;
        for (FuSa.Finding f : scanBlanketFallback(artifactFile, fields)) {
            if (ruleBSuppressed) {
                findings.add(withDisposition(f, FuSa.Disposition.accepted));
            } else {
                findings.add(f);
                warnUnsuppressed = true;
            }
        }
        return new Result(findings, blocking, warnUnsuppressed);
    }

    private static FuSa.Finding withDisposition(FuSa.Finding f, FuSa.Disposition d) {
        return new FuSa.Finding(f.ruleId(), f.severity(), f.message(), f.location(), f.category(),
                f.standard(), f.clause(), f.remediation(), d, f.fingerprint());
    }

    /** Human-readable rendering of a {@link Result} for a command's text output / stderr diagnostics. */
    //fusa:req REQ-QB004
    public static String renderText(Result r) {
        if (r.findings().isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        sb.append("Content-quality baseline (x-FuSa spec §1.6):\n");
        for (FuSa.Finding f : r.findings()) {
            String tag = f.disposition() != FuSa.Disposition.open ? "  [" + f.disposition() + "]" : "";
            sb.append(String.format(Locale.ROOT, "  %-7s %-14s %s%s%n",
                    f.severity(), f.ruleId(), f.message(), tag));
        }
        return sb.toString();
    }
}
