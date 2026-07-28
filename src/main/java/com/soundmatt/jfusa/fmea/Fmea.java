package com.soundmatt.jfusa.fmea;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.attestation.Attestation;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.qualitybar.QualityBar;
import com.soundmatt.jfusa.trace.Trace;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Design FMEA (dFMEA) — derives failure modes and effects from the project's
 * public methods, per IEC 60812:2018 / the AIAG-VDA FMEA Handbook's structure
 * (x-FuSa spec §9.2). Produces {@code fmea.json} and {@code fmea.csv}.
 */
public final class Fmea {

    public static final String FMEA_JSON = "fmea.json";
    public static final String FMEA_CSV = "fmea.csv";

    /** Named per §9.2: this tool uses a qualitative high/medium/low scale, not a numeric 1-10 table. */
    public static final String RATING_SCALE = "qualitative-high-medium-low";

    /** Denominator methodology for {@code summary.coveragePct} — documented honestly, not inflated. */
    public static final String COMPONENTS_INVENTORY_METHOD =
            "same public-method inventory as 'trace --func-coverage' (§1.4.1): public methods excluding "
                    + "getters/setters, constructors, and id()/description()/activate() shims";

    /**
     * Method names excluded from FMEA derivation on top of {@code trace --func-coverage}'s own
     * exemption set (getters/setters/{@code id}/{@code description}/{@code activate}) — these
     * aren't safety-relevant failure surfaces even though {@code trace}'s denominator doesn't
     * exempt them, which is fine: excluding *more* here only keeps {@code componentsAnalyzed} a
     * stricter subset of {@code componentsInProject} (§9.2), never the reverse.
     */
    private static final Set<String> ADDITIONAL_EXEMPT_METHOD_NAMES =
            Set.of("main", "equals", "hashCode", "toString");

    private Fmea() {}

    public record FailureMode(
            String id, String component, String method, String item, String file,
            String failureMode, String effect, String cause, String severity,
            String occurrence, String detection, String actionPriority,
            List<String> mitigations, List<String> requirementIds) {}

    public record Summary(int total, int highPriority, int componentsAnalyzed, int componentsInProject,
                           double coveragePct, String componentsInventoryMethod) {}

    public record FmeaReport(List<FailureMode> entries, Summary summary, Attestation attestation) {}

    // ── Derivation — one entry per public method, content keyed off its real signature ──

    //fusa:req REQ-FMEA001
    public static List<FailureMode> derive(Path root, Config cfg) throws IOException {
        List<FailureMode> entries = new ArrayList<>();
        int id = 1;
        // Reuses trace --func-coverage's own scanner (§1.6 rule 4 implementer guidance, spec
        // v1.15.0) instead of a second, independently-drifting regex — this is what keeps
        // componentsAnalyzed a provable subset of componentsInProject (x-FuSa/java-FuSa#33).
        for (Trace.ComponentMethod cm : Trace.scanComponentMethods(root, cfg)) {
            String method = cm.name();
            if (ADDITIONAL_EXEMPT_METHOD_NAMES.contains(method)) continue;
            String component = cm.file().substring(cm.file().lastIndexOf('/') + 1).replace(".java", "");
            String returnType = cm.returnType();
            String params = cm.params();

            String sev = methodSeverity(method);
            int paramCount = params.isBlank() ? 0 : params.split(",").length;

            entries.add(new FailureMode(
                    "FMEA-" + String.format("%03d", id++),
                    component, method, component + "." + method, cm.file(),
                    failureModeFor(component, method, returnType),
                    effectFor(component, method, sev),
                    causeFor(method, paramCount, returnType),
                    sev, "Low", "Code review + unit test coverage",
                    actionPriority(sev), List.of(), List.of()));
        }
        return entries;
    }

    static String methodSeverity(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.contains("safe") || lower.contains("shutdown") || lower.contains("stop")
                || lower.contains("halt") || lower.contains("reset")) return "high";
        if (lower.contains("check") || lower.contains("validate") || lower.contains("verify")
                || lower.contains("monitor") || lower.contains("detect")) return "medium";
        return "low";
    }

    static String actionPriority(String severity) { return severity; }

    /**
     * failureMode is keyed off the method's own component/name/return-type shape, per §1.6.1 rule
     * B — a fixed sentence repeated for every entry (the original, non-conformant behaviour this
     * replaces) is exactly the "blanket qualitative fallback" the spec's content-quality audit found.
     */
    static String failureModeFor(String component, String method, String returnType) {
        return component + "." + method + "() " + returnTypeFailureDescription(returnType)
                + " or throws an unexpected exception";
    }

    static String returnTypeFailureDescription(String returnType) {
        String t = returnType == null ? "" : returnType.trim();
        String bare = t.replace("[]", "").trim();
        if (t.isEmpty() || t.equals("void")) return "does not signal a fault through its return value";
        if (bare.equalsIgnoreCase("boolean") || bare.equals("Boolean")) return "returns an incorrect boolean result";
        if (t.endsWith("[]") || bare.startsWith("List") || bare.startsWith("Set") || bare.startsWith("Map")
                || bare.startsWith("Collection")) return "returns an incomplete or malformed collection";
        if (bare.equals("String")) return "returns malformed or truncated text";
        if (Set.of("int", "long", "double", "float", "short", "byte",
                "Integer", "Long", "Double", "Float", "Short", "Byte").contains(bare)) {
            return "returns an out-of-range or incorrect numeric value";
        }
        return "returns an incorrect value";
    }

    static String effectFor(String component, String method, String severity) {
        return "Safety function output invalid in " + component + "." + method
                + "() — downstream logic depending on its result may act on incorrect data ("
                + severity + "-severity path)";
    }

    static String causeFor(String method, int paramCount, String returnType) {
        return "Implementation defect in " + method + "(" + paramCount + " parameter(s), returns "
                + (returnType == null || returnType.isBlank() ? "void" : returnType.trim()) + ")";
    }

    // ── Build — entries + coverage summary + carried-forward attestation ────

    //fusa:req REQ-FMEA002
    public static FmeaReport build(Path root, Config cfg) throws IOException {
        List<FailureMode> entries = derive(root, cfg);
        int analyzed = entries.size();
        int inProject = Trace.computeFuncCoverage(root, cfg).totalFunctions();
        double coveragePct = inProject == 0 ? 100.0 : clampCoveragePct(round1(100.0 * analyzed / inProject));
        int highPriority = (int) entries.stream().filter(e -> "high".equals(e.actionPriority())).count();
        Summary summary = new Summary(entries.size(), highPriority, analyzed, inProject, coveragePct,
                COMPONENTS_INVENTORY_METHOD);
        Attestation existing = loadExistingAttestation(root);
        return new FmeaReport(entries, summary, existing);
    }

    /**
     * §9.2: {@code coveragePct} MUST NOT exceed 100. The scanner-reuse in {@link #derive} (via
     * {@link Trace#scanComponentMethods}) makes {@code componentsAnalyzed} a provable subset of
     * {@code componentsInProject} by construction (x-FuSa/java-FuSa#33), but this clamp is a
     * defensive backstop per spec v1.15.0's explicit MUST — never trust a single code path to keep
     * an invariant an evidence artifact depends on.
     */
    //fusa:req REQ-FMEA007
    public static double clampCoveragePct(double pct) { return Math.min(100.0, pct); }

    private static double round1(double v) { return Math.round(v * 10.0) / 10.0; }

    static Attestation loadExistingAttestation(Path root) throws IOException {
        Path f = root.resolve(FMEA_JSON);
        if (!Files.exists(f)) return null;
        try {
            return Attestation.fromJson(Json.parseObject(Files.readString(f)));
        } catch (Json.JsonParseException e) {
            return null;
        }
    }

    // ── Content-quality baseline (§1.6/§1.6.1) ────────────────────────────────

    /** failureMode/effect/cause are the fields §1.6.1 rule B targets directly for an FMEA. */
    //fusa:req REQ-FMEA006
    public static List<QualityBar.Field> qualityBarFields(List<FailureMode> entries) {
        List<QualityBar.Field> fields = new ArrayList<>();
        for (FailureMode e : entries) {
            fields.add(new QualityBar.Field(e.id(), "failureMode", e.failureMode()));
            fields.add(new QualityBar.Field(e.id(), "effect", e.effect()));
            fields.add(new QualityBar.Field(e.id(), "cause", e.cause()));
        }
        return fields;
    }

    //fusa:req REQ-FMEA006
    public static List<Object> substantiveContent(List<FailureMode> entries) {
        List<Object> out = new ArrayList<>();
        for (FailureMode e : entries) out.add(entryToMap(e));
        return out;
    }

    private static Map<String, Object> entryToMap(FailureMode e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", e.id());
        m.put("item", e.item());
        m.put("file", e.file());
        m.put("failureMode", e.failureMode());
        m.put("effect", e.effect());
        m.put("cause", e.cause());
        m.put("severity", e.severity());
        m.put("occurrence", e.occurrence());
        m.put("detection", e.detection());
        m.put("actionPriority", e.actionPriority());
        m.put("mitigations", e.mitigations());
        m.put("requirementIds", e.requirementIds());
        return m;
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    //fusa:req REQ-FMEA003
    public static void writeJson(Path root, FmeaReport report, String outputFile) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "fmea-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("ratingScale", RATING_SCALE);
        w.key("entries"); w.rawValue(substantiveContent(report.entries()));
        w.key("summary"); w.objectStart();
        w.field("total", report.summary().total());
        w.field("highPriority", report.summary().highPriority());
        w.field("componentsAnalyzed", report.summary().componentsAnalyzed());
        w.field("componentsInProject", report.summary().componentsInProject());
        w.field("coveragePct", report.summary().coveragePct());
        w.field("componentsInventoryMethod", report.summary().componentsInventoryMethod());
        w.objectEnd();
        if (report.attestation() != null) report.attestation().writeJson(w);
        w.objectEnd();
        String path = (outputFile == null || outputFile.isBlank()) ? FMEA_JSON : outputFile;
        Files.writeString(root.resolve(path), w.toPretty() + "\n");
    }

    //fusa:req REQ-FMEA003
    public static void writeCsv(Path root, List<FailureMode> entries) throws IOException {
        var sb = new StringBuilder();
        sb.append("ID,Item,File,Failure Mode,Effect,Cause,Severity,Occurrence,Detection,Action Priority\n");
        for (FailureMode e : entries) {
            sb.append(csv(e.id())).append(',').append(csv(e.item())).append(',').append(csv(e.file())).append(',')
                    .append(csv(e.failureMode())).append(',').append(csv(e.effect())).append(',')
                    .append(csv(e.cause())).append(',').append(csv(e.severity())).append(',')
                    .append(csv(e.occurrence())).append(',').append(csv(e.detection())).append(',')
                    .append(csv(e.actionPriority())).append('\n');
        }
        Files.writeString(root.resolve(FMEA_CSV), sb.toString());
    }

    static String csv(String s) { return "\"" + s.replace("\"", "\"\"") + "\""; }

    // ── Text rendering ────────────────────────────────────────────────────────

    //fusa:req REQ-FMEA004
    public static String renderText(FmeaReport report) {
        var sb = new StringBuilder();
        sb.append("Design FMEA (dFMEA)\n");
        sb.append("Rating scale: ").append(RATING_SCALE).append('\n');
        sb.append(String.format(Locale.ROOT,
                "Items: %d total, %d high-priority, coverage %.1f%% (%d/%d, %s)%n%n",
                report.summary().total(), report.summary().highPriority(), report.summary().coveragePct(),
                report.summary().componentsAnalyzed(), report.summary().componentsInProject(),
                report.summary().componentsInventoryMethod()));
        for (FailureMode e : report.entries()) {
            sb.append("[").append(e.actionPriority().toUpperCase(Locale.ROOT)).append("] ")
                    .append(e.id()).append(" — ").append(e.item()).append('\n');
            sb.append("  Failure mode: ").append(e.failureMode()).append('\n');
            sb.append("  Effect:       ").append(e.effect()).append('\n');
            sb.append("  Cause:        ").append(e.cause()).append('\n');
        }
        return sb.toString();
    }
}
