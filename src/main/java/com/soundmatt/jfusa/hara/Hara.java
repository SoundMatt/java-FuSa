package com.soundmatt.jfusa.hara;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.attestation.Attestation;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.qualitybar.QualityBar;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Hazard Analysis and Risk Assessment (HARA) — ISO 26262-3:2018 Clause 6.
 *
 * <p>{@code .fusa-hara.json} is an <b>input</b> file (x-FuSa spec §1.2.5): a
 * project author writes/maintains it, and {@link #load} / the {@code hara}
 * command validate and report on it — this package never invents hazards.
 * {@link #init} scaffolds an <b>empty</b> template when the file is absent,
 * never dummy rows (§1.6 rule 1).
 */
public final class Hara {

    public static final String HARA_FILE = ".fusa-hara.json";

    private Hara() {}

    // ── §1.2.5 document model ─────────────────────────────────────────────────

    public record OperationalSituation(String id, String description) {}

    public record RiskRating(String severity, String exposure, String controllability, String asil) {}

    public record Hazard(String id, String description, String source,
                          List<String> situations, RiskRating risk, List<String> safetyGoals) {}

    public record SafetyGoal(String id, String description, List<String> hazards,
                              String asil, String safeState, List<String> fssrRefs) {}

    public record HaraDoc(String project, String standard, String createdAt,
                           List<OperationalSituation> situations, List<Hazard> hazards,
                           List<SafetyGoal> safetyGoals, Attestation attestation) {}

    public record Completeness(int totalHazards, int hazardsWithAsil, int hazardsWithSafetyGoal,
                                int totalSafetyGoals, int safetyGoalsWithFssrRefs, int danglingReferences) {}

    public record ValidationFinding(String message) {}

    // ── ASIL determination — ISO 26262-3:2018 Table 4 ────────────────────────

    /**
     * Derives the ASIL from numeric Severity/Exposure/Controllability per
     * ISO 26262-3:2018 Table 4, using the standard's additive risk-point model:
     * the class points S (1..3) + E (1..4) + C (1..3) are summed, and
     * <pre>
     *   sum &le; 6 &rarr; QM,  7 &rarr; A,  8 &rarr; B,  9 &rarr; C,  10 &rarr; D
     * </pre>
     * so ASIL-D arises only at the single worst case S3/E4/C3 (3+4+3=10).
     * A severity, exposure, or controllability class of 0 (e.g. S0/E0/C0) is
     * always QM. This replaces a hand-authored lookup table whose S2/S3 rows
     * were column-shifted and inflated the derived ASIL for most inputs.
     */
    //fusa:req REQ-HARA001
    public static String deriveAsil(int s, int e, int c) {
        if (s <= 0 || e <= 0 || c <= 0) return "QM";
        int si = Math.min(s, 3);
        int ei = Math.min(e, 4);
        int ci = Math.min(c, 3);
        int points = si + ei + ci;
        String bare = switch (points) {
            case 7 -> "A";
            case 8 -> "B";
            case 9 -> "C";
            case 10 -> "D";
            default -> "QM"; // points <= 6
        };
        return "QM".equals(bare) ? "QM" : "ASIL-" + bare;
    }

    /** Derives the ASIL from the §1.2.5 letter+digit form ("S2", "E3", "C1"). */
    //fusa:req REQ-HARA001
    public static String deriveAsil(String severity, String exposure, String controllability) {
        return deriveAsil(parseLevel(severity), parseLevel(exposure), parseLevel(controllability));
    }

    private static int parseLevel(String s) {
        if (s == null || s.length() < 2) return 0;
        try {
            return Integer.parseInt(s.substring(1).trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    // ── init — scaffold an EMPTY template (never dummy rows, §1.6 rule 1) ────

    //fusa:req REQ-HARA002
    public static void init(Path root, String project, String standard) throws IOException {
        if (Files.exists(root.resolve(HARA_FILE))) return;
        var w = new Json.Writer();
        w.objectStart();
        w.field("project", project == null ? "" : project);
        w.field("standard", standard == null || standard.isBlank() ? "generic" : standard);
        w.field("createdAt", Instant.now().toString());
        w.key("operationalSituations"); w.arrayStart(); w.arrayEnd();
        w.key("hazards"); w.arrayStart(); w.arrayEnd();
        w.key("safetyGoals"); w.arrayStart(); w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(HARA_FILE), w.toPretty() + "\n");
    }

    // ── load — parse .fusa-hara.json verbatim ────────────────────────────────

    /** Parses {@code .fusa-hara.json}; returns an empty doc (empty collections) if absent. */
    //fusa:req REQ-HARA003
    public static HaraDoc load(Path root) throws IOException {
        Path f = root.resolve(HARA_FILE);
        if (!Files.exists(f)) {
            return new HaraDoc("", "", "", List.of(), List.of(), List.of(), null);
        }
        Map<String, Object> doc = Json.parseObject(Files.readString(f));
        List<OperationalSituation> situations = new ArrayList<>();
        for (Object o : Json.arr(doc, "operationalSituations")) {
            if (o instanceof Map<?, ?> m) {
                @SuppressWarnings("unchecked") var mm = (Map<String, Object>) m;
                situations.add(new OperationalSituation(Json.str(mm, "id", ""), Json.str(mm, "description", "")));
            }
        }
        List<Hazard> hazards = new ArrayList<>();
        for (Object o : Json.arr(doc, "hazards")) {
            if (o instanceof Map<?, ?> m) {
                @SuppressWarnings("unchecked") var mm = (Map<String, Object>) m;
                Map<String, Object> riskMap = Json.obj(mm, "risk");
                RiskRating risk = new RiskRating(
                        Json.str(riskMap, "severity", ""), Json.str(riskMap, "exposure", ""),
                        Json.str(riskMap, "controllability", ""), Json.str(riskMap, "asil", ""));
                hazards.add(new Hazard(Json.str(mm, "id", ""), Json.str(mm, "description", ""),
                        Json.str(mm, "source", ""), stringList(mm, "situations"), risk,
                        stringList(mm, "safetyGoals")));
            }
        }
        List<SafetyGoal> goals = new ArrayList<>();
        for (Object o : Json.arr(doc, "safetyGoals")) {
            if (o instanceof Map<?, ?> m) {
                @SuppressWarnings("unchecked") var mm = (Map<String, Object>) m;
                goals.add(new SafetyGoal(Json.str(mm, "id", ""), Json.str(mm, "description", ""),
                        stringList(mm, "hazards"), Json.str(mm, "asil", ""),
                        Json.str(mm, "safeState", ""), stringList(mm, "fssrRefs")));
            }
        }
        return new HaraDoc(Json.str(doc, "project", ""), Json.str(doc, "standard", ""),
                Json.str(doc, "createdAt", ""), situations, hazards, goals, Attestation.fromJson(doc));
    }

    private static List<String> stringList(Map<String, Object> m, String key) {
        List<String> out = new ArrayList<>();
        for (Object o : Json.arr(m, key)) if (o instanceof String s) out.add(s);
        return out;
    }

    /** Loads every requirement id from {@code .fusa-reqs.json}, for {@code fssrRefs} resolution. */
    //fusa:req REQ-HARA003
    public static Set<String> loadReqIds(Path root) throws IOException {
        Path f = root.resolve(".fusa-reqs.json");
        if (!Files.exists(f)) return Set.of();
        Map<String, Object> doc = Json.parseObject(Files.readString(f));
        Set<String> ids = new LinkedHashSet<>();
        for (Object o : Json.arr(doc, "requirements")) {
            if (o instanceof Map<?, ?> m) {
                @SuppressWarnings("unchecked") var mm = (Map<String, Object>) m;
                String id = Json.str(mm, "id", "");
                if (!id.isBlank()) ids.add(id);
            }
        }
        return ids;
    }

    // ── Validation — referential integrity + MUST-field completeness ────────

    /** Effective ASIL for a hazard: derived from S×E×C when {@code standard} is iso26262, else as-given. */
    //fusa:req REQ-HARA004
    public static String effectiveAsil(String standard, RiskRating risk) {
        if (risk == null) return "";
        if ("iso26262".equalsIgnoreCase(standard)) {
            return deriveAsil(risk.severity(), risk.exposure(), risk.controllability());
        }
        return risk.asil();
    }

    /** Runs the §1.2.5 MUST checks: referential integrity, ASIL/fssrRefs completeness. */
    //fusa:req REQ-HARA004
    public static List<ValidationFinding> validate(HaraDoc doc, Set<String> reqIds) {
        List<ValidationFinding> out = new ArrayList<>();
        Set<String> situationIds = new LinkedHashSet<>();
        for (OperationalSituation s : doc.situations()) situationIds.add(s.id());
        Set<String> hazardIds = new LinkedHashSet<>();
        for (Hazard h : doc.hazards()) hazardIds.add(h.id());
        Set<String> goalIds = new LinkedHashSet<>();
        for (SafetyGoal g : doc.safetyGoals()) goalIds.add(g.id());

        for (Hazard h : doc.hazards()) {
            if (h.risk() == null || h.risk().severity().isBlank() || h.risk().exposure().isBlank()
                    || h.risk().controllability().isBlank()) {
                out.add(new ValidationFinding("hazard " + h.id() + " has an incomplete risk rating — "
                        + "severity, exposure, and controllability must all be set"));
            }
            if (h.safetyGoals().isEmpty()) {
                out.add(new ValidationFinding("hazard " + h.id() + " has no linked safety goal"));
            }
            for (String sid : h.situations()) {
                if (!situationIds.contains(sid)) {
                    out.add(new ValidationFinding(
                            "hazard " + h.id() + " references unknown operational situation " + sid));
                }
            }
            for (String gid : h.safetyGoals()) {
                if (!goalIds.contains(gid)) {
                    out.add(new ValidationFinding("hazard " + h.id() + " references unknown safety goal " + gid));
                }
            }
        }
        for (SafetyGoal g : doc.safetyGoals()) {
            if (g.fssrRefs().isEmpty()) {
                out.add(new ValidationFinding("safety goal " + g.id() + " has no fssrRefs — a safety goal MUST "
                        + "decompose into at least one functional safety requirement (x-FuSa spec §1.2.5, "
                        + "ISO 26262-8 Clause 6)"));
            }
            for (String reqId : g.fssrRefs()) {
                if (!reqIds.contains(reqId)) {
                    out.add(new ValidationFinding(
                            "safety goal " + g.id() + " fssrRefs references unknown requirement " + reqId
                                    + " (not found in .fusa-reqs.json)"));
                }
            }
            for (String hid : g.hazards()) {
                if (!hazardIds.contains(hid)) {
                    out.add(new ValidationFinding("safety goal " + g.id() + " references unknown hazard " + hid));
                }
            }
        }
        return out;
    }

    /** Rolls up the §9.2 {@code completeness} block: MUST/SHOULD field coverage + dangling references. */
    //fusa:req REQ-HARA005
    public static Completeness computeCompleteness(HaraDoc doc, Set<String> reqIds) {
        Set<String> situationIds = new LinkedHashSet<>();
        for (OperationalSituation s : doc.situations()) situationIds.add(s.id());
        Set<String> hazardIds = new LinkedHashSet<>();
        for (Hazard h : doc.hazards()) hazardIds.add(h.id());
        Set<String> goalIds = new LinkedHashSet<>();
        for (SafetyGoal g : doc.safetyGoals()) goalIds.add(g.id());

        int hazardsWithAsil = 0, hazardsWithSafetyGoal = 0, dangling = 0;
        for (Hazard h : doc.hazards()) {
            String asil = effectiveAsil(doc.standard(), h.risk());
            if (!asil.isBlank()) hazardsWithAsil++;
            if (!h.safetyGoals().isEmpty()) hazardsWithSafetyGoal++;
            for (String sid : h.situations()) if (!situationIds.contains(sid)) dangling++;
            for (String gid : h.safetyGoals()) if (!goalIds.contains(gid)) dangling++;
        }
        int goalsWithFssr = 0;
        for (SafetyGoal g : doc.safetyGoals()) {
            if (!g.fssrRefs().isEmpty()) goalsWithFssr++;
            for (String reqId : g.fssrRefs()) if (!reqIds.contains(reqId)) dangling++;
            for (String hid : g.hazards()) if (!hazardIds.contains(hid)) dangling++;
        }
        return new Completeness(doc.hazards().size(), hazardsWithAsil, hazardsWithSafetyGoal,
                doc.safetyGoals().size(), goalsWithFssr, dangling);
    }

    // ── Content-quality baseline (§1.6/§1.6.1) ────────────────────────────────

    /** Qualitative fields subject to FUSA-STUB001/002 scanning: hazard and safety-goal descriptions. */
    //fusa:req REQ-HARA006
    public static List<QualityBar.Field> qualityBarFields(HaraDoc doc) {
        List<QualityBar.Field> fields = new ArrayList<>();
        for (Hazard h : doc.hazards()) fields.add(new QualityBar.Field(h.id(), "description", h.description()));
        for (SafetyGoal g : doc.safetyGoals()) fields.add(new QualityBar.Field(g.id(), "description", g.description()));
        return fields;
    }

    /** The substantive content §1.6.2 hashes over: the three cross-referenced collections. */
    //fusa:req REQ-HARA006
    public static Map<String, Object> substantiveContent(HaraDoc doc) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("operationalSituations", situationsToMaps(doc.situations()));
        m.put("hazards", hazardsToMaps(doc.hazards()));
        m.put("safetyGoals", goalsToMaps(doc.safetyGoals()));
        return m;
    }

    private static List<Object> situationsToMaps(List<OperationalSituation> l) {
        List<Object> out = new ArrayList<>();
        for (OperationalSituation s : l) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", s.id());
            m.put("description", s.description());
            out.add(m);
        }
        return out;
    }

    private static List<Object> hazardsToMaps(List<Hazard> l) {
        List<Object> out = new ArrayList<>();
        for (Hazard h : l) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", h.id());
            m.put("description", h.description());
            if (!h.source().isBlank()) m.put("source", h.source());
            m.put("situations", h.situations());
            Map<String, Object> risk = new LinkedHashMap<>();
            risk.put("severity", h.risk().severity());
            risk.put("exposure", h.risk().exposure());
            risk.put("controllability", h.risk().controllability());
            risk.put("asil", h.risk().asil());
            m.put("risk", risk);
            m.put("safetyGoals", h.safetyGoals());
            out.add(m);
        }
        return out;
    }

    private static List<Object> goalsToMaps(List<SafetyGoal> l) {
        List<Object> out = new ArrayList<>();
        for (SafetyGoal g : l) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", g.id());
            m.put("description", g.description());
            m.put("hazards", g.hazards());
            m.put("asil", g.asil());
            if (!g.safeState().isBlank()) m.put("safeState", g.safeState());
            m.put("fssrRefs", g.fssrRefs());
            out.add(m);
        }
        return out;
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    /** {@code --format json}: §3.1 header + verbatim §1.2.5 content + {@code completeness} + attestation passthrough. */
    //fusa:req REQ-HARA007
    public static String renderJson(HaraDoc doc, Completeness completeness) {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "hara-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("project", doc.project());
        w.field("standard", doc.standard());
        w.fieldIfNonBlank("createdAt", doc.createdAt());

        w.key("operationalSituations"); w.rawValue(situationsToMaps(doc.situations()));

        w.key("hazards"); w.arrayStart();
        for (Hazard h : doc.hazards()) {
            w.objectStart();
            w.field("id", h.id());
            w.field("description", h.description());
            w.fieldIfNonBlank("source", h.source());
            w.key("situations"); w.rawValue(h.situations());
            w.key("risk"); w.objectStart();
            w.field("severity", h.risk().severity());
            w.field("exposure", h.risk().exposure());
            w.field("controllability", h.risk().controllability());
            w.field("asil", effectiveAsil(doc.standard(), h.risk()));
            w.objectEnd();
            w.key("safetyGoals"); w.rawValue(h.safetyGoals());
            w.objectEnd();
        }
        w.arrayEnd();

        w.key("safetyGoals"); w.arrayStart();
        for (SafetyGoal g : doc.safetyGoals()) {
            w.objectStart();
            w.field("id", g.id());
            w.field("description", g.description());
            w.key("hazards"); w.rawValue(g.hazards());
            w.field("asil", g.asil());
            w.fieldIfNonBlank("safeState", g.safeState());
            w.key("fssrRefs"); w.rawValue(g.fssrRefs());
            w.objectEnd();
        }
        w.arrayEnd();

        w.key("completeness"); w.objectStart();
        w.field("totalHazards", completeness.totalHazards());
        w.field("hazardsWithAsil", completeness.hazardsWithAsil());
        w.field("hazardsWithSafetyGoal", completeness.hazardsWithSafetyGoal());
        w.field("totalSafetyGoals", completeness.totalSafetyGoals());
        w.field("safetyGoalsWithFssrRefs", completeness.safetyGoalsWithFssrRefs());
        w.field("danglingReferences", completeness.danglingReferences());
        w.objectEnd();

        if (doc.attestation() != null) doc.attestation().writeJson(w);
        w.objectEnd();
        return w.toPretty();
    }

    //fusa:req REQ-HARA007
    public static String renderText(HaraDoc doc, List<ValidationFinding> findings, Completeness completeness) {
        var sb = new StringBuilder();
        sb.append("HARA — Hazard Analysis and Risk Assessment\n");
        sb.append("Project: ").append(doc.project()).append("  Standard: ").append(doc.standard()).append('\n');
        sb.append("=".repeat(70)).append('\n');

        sb.append(String.format("%-8s %s%n", "ID", "Operational Situation"));
        for (OperationalSituation s : doc.situations()) {
            sb.append(String.format("%-8s %s%n", s.id(), s.description()));
        }
        sb.append('\n');

        sb.append(String.format("%-8s %-30s %-4s %-4s %-4s %-8s %s%n",
                "ID", "Hazard", "S", "E", "C", "ASIL", "Safety Goals"));
        sb.append("-".repeat(70)).append('\n');
        for (Hazard h : doc.hazards()) {
            String desc = h.description();
            sb.append(String.format("%-8s %-30s %-4s %-4s %-4s %-8s %s%n",
                    h.id(), desc.substring(0, Math.min(29, desc.length())),
                    h.risk().severity(), h.risk().exposure(), h.risk().controllability(),
                    effectiveAsil(doc.standard(), h.risk()), String.join(",", h.safetyGoals())));
        }
        sb.append('\n');

        sb.append(String.format("%-8s %-30s %-8s %s%n", "ID", "Safety Goal", "ASIL", "fssrRefs"));
        sb.append("-".repeat(70)).append('\n');
        for (SafetyGoal g : doc.safetyGoals()) {
            String desc = g.description();
            sb.append(String.format("%-8s %-30s %-8s %s%n",
                    g.id(), desc.substring(0, Math.min(29, desc.length())), g.asil(),
                    String.join(",", g.fssrRefs())));
        }

        sb.append("\nCompleteness: ").append(completeness.hazardsWithAsil()).append('/')
                .append(completeness.totalHazards()).append(" hazards ASIL-rated, ")
                .append(completeness.safetyGoalsWithFssrRefs()).append('/')
                .append(completeness.totalSafetyGoals()).append(" safety goals have fssrRefs, ")
                .append(completeness.danglingReferences()).append(" dangling reference(s)\n");

        if (!findings.isEmpty()) {
            sb.append("\nValidation findings (").append(findings.size()).append("):\n");
            for (ValidationFinding f : findings) sb.append("  - ").append(f.message()).append('\n');
        }
        return sb.toString();
    }
}
