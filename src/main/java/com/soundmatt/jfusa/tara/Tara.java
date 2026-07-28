package com.soundmatt.jfusa.tara;

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
 * Threat Analysis and Risk Assessment (TARA) per ISO/SAE 21434:2021 Clause 15
 * (x-FuSa spec §9.2). Generates {@code tara.json} and {@code tara.md}.
 *
 * <p>{@code threats[]} is a fixed catalogue of cybersecurity threats generic to
 * a JVM-based safety-tooling CLI — it is not a per-project asset-discovery
 * scan (see {@link #ASSET_INVENTORY_METHOD}, disclosed honestly in
 * {@code summary} rather than presented as an exhaustive inventory).
 */
public final class Tara {

    public static final String TARA_JSON = "tara.json";
    public static final String TARA_MD = "tara.md";

    /** Denominator methodology for {@code summary.coveragePct} — documented honestly, not inflated. */
    public static final String ASSET_INVENTORY_METHOD =
            "fixed cross-project ISO 21434 threat catalogue (asset classes common to a JVM-based "
                    + "safety-tooling CLI) — not a per-project asset-discovery scan; coveragePct reflects "
                    + "full analysis of this tool's built-in catalogue, not an exhaustive inventory of the "
                    + "analyzed project's actual assets";

    private Tara() {}

    public record ImpactRating(String safety, String financial, String operational, String privacy) {}

    public record ThreatScenario(
            String id, String asset, String threat, String cwe, String attackVector,
            String attackFeasibility, ImpactRating impact, String risk, String treatment,
            List<String> mitigations, String cyberRuleId) {}

    public record Summary(int assetsAnalyzed, int assetsInProject, double coveragePct, String assetInventoryMethod) {}

    public record TaraReport(List<ThreatScenario> threats, Summary summary, Attestation attestation) {}

    // ── Risk derivation — feasibility × highest SFOP impact ─────────────────

    /**
     * Rank for the x-FuSa family's own closed {@code impact.{safety,financial,operational,privacy}}
     * enum (x-FuSa spec §9.2, "Closed enums"): {@code critical} | {@code major} | {@code moderate} |
     * {@code negligible}. This is a deliberately distinct vocabulary from {@code attackFeasibility}'s
     * {@code high|medium|low|very-low} — the two are different scales for different questions
     * (damage vs. likelihood) and a tool MUST NOT conflate them (x-FuSa/java-FuSa#34).
     */
    private static int impactRank(String impact) {
        return switch (impact) {
            case "critical" -> 3;
            case "major" -> 2;
            case "moderate" -> 1;
            default -> 0; // negligible
        };
    }

    private static int feasibilityRank(String feasibility) {
        return switch (feasibility) {
            case "high" -> 3;
            case "medium" -> 2;
            case "low" -> 1;
            default -> 0; // very-low
        };
    }

    /**
     * x-FuSa spec §9.2 "Risk combination table" — the family's own canonical convention (ISO/SAE
     * 21434 Clause 15.3 leaves the determination method organization-defined). Row = highest SFOP
     * impact rank ({@link #impactRank}, 0=negligible..3=critical); column = attackFeasibility rank
     * ({@link #feasibilityRank}, 0=very-low..3=high).
     */
    private static final String[][] RISK_TABLE = {
            // very-low,  low,      medium,     high        (feasibility →)
            { "low",      "low",    "low",      "low"      }, // negligible
            { "low",      "low",    "medium",   "medium"   }, // moderate
            { "medium",   "medium", "high",     "high"     }, // major
            { "medium",   "high",   "critical", "critical" }, // critical
    };

    /** Highest of the four SFOP axes — ISO 21434 Clause 15.7: overall risk uses the worst-case damage. */
    //fusa:req REQ-TARA006
    public static String highestImpact(ImpactRating ir) {
        String best = ir.safety();
        for (String i : List.of(ir.financial(), ir.operational(), ir.privacy())) {
            if (impactRank(i) > impactRank(best)) best = i;
        }
        return best;
    }

    /**
     * Derives {@code risk} from {@code attackFeasibility} × the highest SFOP impact axis, per the
     * x-FuSa spec §9.2 risk-combination table verbatim.
     */
    //fusa:req REQ-TARA006
    public static String deriveRisk(ImpactRating impact, String feasibility) {
        int i = impactRank(highestImpact(impact));
        int f = feasibilityRank(feasibility);
        return RISK_TABLE[i][f];
    }

    // ── Fixed catalogue ───────────────────────────────────────────────────────

    private record ScenarioSpec(String id, String asset, String threat, String cwe, String attackVector,
                                 String feasibility, ImpactRating impact, String treatment,
                                 List<String> mitigations, String cyberRuleId) {}

    private static ImpactRating impact(String s, String f, String o, String p) {
        return new ImpactRating(s, f, o, p);
    }

    // Impact axes use the x-FuSa family's own closed enum (spec §9.2): critical | major |
    // moderate | negligible — NOT the high|medium|low vocabulary attackFeasibility uses
    // (x-FuSa/java-FuSa#34). attackFeasibility itself stays high|medium|low|very-low, unchanged.
    private static List<ScenarioSpec> catalogue(String projectName) {
        return List.of(
                new ScenarioSpec("TARA-001", projectName + " build artifacts / SBOM",
                        "Supply-chain compromise via a malicious or tampered dependency reaching the release build",
                        "CWE-829", "network",
                        "low", impact("critical", "major", "moderate", "negligible"), "mitigate",
                        List.of("Pin dependency versions", "Verify checksums via SBOM", "SLSA provenance (fusaops slsa)"),
                        ""),
                new ScenarioSpec("TARA-002", "Configuration files",
                        "Credential exposure via a hardcoded secret committed to source",
                        "CWE-259", "local",
                        "high", impact("major", "major", "moderate", "moderate"), "mitigate",
                        List.of("Use environment variables or a secrets manager", "Enforce CYBER005/CYBER006"),
                        "CYBER005"),
                new ScenarioSpec("TARA-003", "Runtime process",
                        "Privilege escalation via command injection into a subprocess call",
                        "CWE-78", "network",
                        "medium", impact("critical", "moderate", "major", "negligible"), "mitigate",
                        List.of("Input validation", "Process isolation", "Least-privilege execution"),
                        ""),
                new ScenarioSpec("TARA-004", "Audit / evidence logs",
                        "Log tampering to conceal malicious activity or a suppressed finding",
                        "CWE-117", "local",
                        "low", impact("major", "moderate", "moderate", "negligible"), "mitigate",
                        List.of("Centralised tamper-evident logging", "Hash chaining"),
                        ""),
                new ScenarioSpec("TARA-005", "Safety decision outputs (fmea/tara/hara/safety-case JSON)",
                        "Integrity violation of a safety-critical evidence artefact after generation",
                        "CWE-345", "network",
                        "medium", impact("critical", "moderate", "moderate", "negligible"), "mitigate",
                        List.of("Digital signatures (fusaops sign)", "Integrity checks on all safety outputs"),
                        ""),
                new ScenarioSpec("TARA-006", "Memory / process resources",
                        "Denial of service via resource exhaustion during analysis of an adversarial input",
                        "CWE-770", "network",
                        "medium", impact("moderate", "moderate", "major", "negligible"), "mitigate",
                        List.of("Input size limits", "Rate limiting", "Circuit breakers"),
                        ""),
                new ScenarioSpec("TARA-007", "JSON parser (internal.Json)",
                        "Data injection or parser DoS via malformed/adversarial input",
                        "CWE-611", "network",
                        "medium", impact("moderate", "negligible", "moderate", "negligible"), "mitigate",
                        List.of("No external entity resolution", "Reject malformed input early"),
                        "")
        );
    }

    // ── Build ─────────────────────────────────────────────────────────────────

    //fusa:req REQ-TARA002
    public static TaraReport build(Path root, String projectName) throws IOException {
        List<ThreatScenario> threats = new ArrayList<>();
        for (ScenarioSpec s : catalogue(projectName)) {
            String risk = deriveRisk(s.impact(), s.feasibility());
            threats.add(new ThreatScenario(s.id(), s.asset(), s.threat(), s.cwe(), s.attackVector(),
                    s.feasibility(), s.impact(), risk, s.treatment(), s.mitigations(), s.cyberRuleId()));
        }
        int analyzed = threats.size();
        int inProject = threats.size(); // fixed catalogue — see ASSET_INVENTORY_METHOD
        Summary summary = new Summary(analyzed, inProject, 100.0, ASSET_INVENTORY_METHOD);
        Attestation existing = loadExistingAttestation(root);
        return new TaraReport(threats, summary, existing);
    }

    static Attestation loadExistingAttestation(Path root) throws IOException {
        Path f = root.resolve(TARA_JSON);
        if (!Files.exists(f)) return null;
        try {
            return Attestation.fromJson(Json.parseObject(Files.readString(f)));
        } catch (Json.JsonParseException e) {
            return null;
        }
    }

    // ── Content-quality baseline (§1.6/§1.6.1) ────────────────────────────────

    /** {@code threat} is the field §1.6.1 rule B names directly for a TARA. */
    //fusa:req REQ-TARA007
    public static List<QualityBar.Field> qualityBarFields(List<ThreatScenario> threats) {
        List<QualityBar.Field> fields = new ArrayList<>();
        for (ThreatScenario t : threats) fields.add(new QualityBar.Field(t.id(), "threat", t.threat()));
        return fields;
    }

    //fusa:req REQ-TARA007
    public static List<Object> substantiveContent(List<ThreatScenario> threats) {
        List<Object> out = new ArrayList<>();
        for (ThreatScenario t : threats) out.add(entryToMap(t));
        return out;
    }

    private static Map<String, Object> entryToMap(ThreatScenario t) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", t.id());
        m.put("asset", t.asset());
        m.put("threat", t.threat());
        if (!t.cwe().isBlank()) m.put("cwe", t.cwe());
        m.put("attackVector", t.attackVector());
        m.put("attackFeasibility", t.attackFeasibility());
        Map<String, Object> impact = new LinkedHashMap<>();
        impact.put("safety", t.impact().safety());
        impact.put("financial", t.impact().financial());
        impact.put("operational", t.impact().operational());
        impact.put("privacy", t.impact().privacy());
        m.put("impact", impact);
        m.put("risk", t.risk());
        m.put("treatment", t.treatment());
        m.put("mitigations", t.mitigations());
        if (!t.cyberRuleId().isBlank()) m.put("cyberRuleId", t.cyberRuleId());
        return m;
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    //fusa:req REQ-TARA003
    public static void writeJson(Path root, TaraReport report, String outputFile) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "tara-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("standard", "iso21434");
        w.key("threats"); w.rawValue(substantiveContent(report.threats()));
        w.key("summary"); w.objectStart();
        w.field("assetsAnalyzed", report.summary().assetsAnalyzed());
        w.field("assetsInProject", report.summary().assetsInProject());
        w.field("coveragePct", report.summary().coveragePct());
        w.field("assetInventoryMethod", report.summary().assetInventoryMethod());
        w.objectEnd();
        if (report.attestation() != null) report.attestation().writeJson(w);
        w.objectEnd();
        String path = (outputFile == null || outputFile.isBlank()) ? TARA_JSON : outputFile;
        Files.writeString(root.resolve(path), w.toPretty() + "\n");
    }

    //fusa:req REQ-TARA003
    public static void writeMarkdown(Path root, TaraReport report, String project) throws IOException {
        var sb = new StringBuilder();
        sb.append("# Threat Analysis and Risk Assessment (TARA)\n\n");
        sb.append("**Project:** ").append(project).append("  \n");
        sb.append("**Standard:** ISO/SAE 21434:2021 Clause 15  \n");
        sb.append("**Generated:** ").append(Instant.now()).append("\n\n");
        sb.append("## Threat Catalogue\n\n");
        sb.append("| ID | Asset | Threat | Feasibility | Safety | Financial | Operational | Privacy | Risk | Treatment |\n");
        sb.append("|---|---|---|---|---|---|---|---|---|---|\n");
        for (ThreatScenario t : report.threats()) {
            sb.append("| ").append(t.id()).append(" | ").append(t.asset()).append(" | ").append(t.threat())
                    .append(" | ").append(t.attackFeasibility())
                    .append(" | ").append(t.impact().safety()).append(" | ").append(t.impact().financial())
                    .append(" | ").append(t.impact().operational()).append(" | ").append(t.impact().privacy())
                    .append(" | ").append(t.risk()).append(" | ").append(t.treatment()).append(" |\n");
        }
        sb.append(String.format(Locale.ROOT, "%n_Coverage: %.1f%% (%d/%d) — %s_%n",
                report.summary().coveragePct(), report.summary().assetsAnalyzed(),
                report.summary().assetsInProject(), report.summary().assetInventoryMethod()));
        Files.writeString(root.resolve(TARA_MD), sb.toString());
    }

    // ── Text rendering ────────────────────────────────────────────────────────

    //fusa:req REQ-TARA004
    public static String renderText(TaraReport report) {
        var sb = new StringBuilder();
        sb.append("Threat Analysis and Risk Assessment (TARA) — ISO/SAE 21434:2021 Clause 15\n\n");
        for (ThreatScenario t : report.threats()) {
            sb.append("[").append(t.risk().toUpperCase(Locale.ROOT)).append("] ")
                    .append(t.id()).append(" — ").append(t.asset()).append('\n');
            sb.append("  Threat: ").append(t.threat()).append('\n');
            sb.append(String.format("  Impact: safety=%s financial=%s operational=%s privacy=%s  Feasibility: %s%n",
                    t.impact().safety(), t.impact().financial(), t.impact().operational(), t.impact().privacy(),
                    t.attackFeasibility()));
            sb.append("  Treatment: ").append(t.treatment()).append('\n');
        }
        sb.append(String.format(Locale.ROOT, "%nCoverage: %.1f%% (%d/%d) — %s%n",
                report.summary().coveragePct(), report.summary().assetsAnalyzed(),
                report.summary().assetsInProject(), report.summary().assetInventoryMethod()));
        return sb.toString();
    }
}
