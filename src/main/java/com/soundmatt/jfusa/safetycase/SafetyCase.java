package com.soundmatt.jfusa.safetycase;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.attestation.Attestation;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.qualitybar.QualityBar;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Safety case assembly — a GSN (Goal Structuring Notation) argument per the
 * GSN Community Standard (Assurance Case Working Group, v3, 2021), built from
 * the evidence artefacts present in the project (x-FuSa spec §9.2).
 */
public final class SafetyCase {

    public static final String SAFETY_CASE_MD = "safety-case.md";
    public static final String SAFETY_CASE_JSON = "safety-case.json";
    public static final String SAFETY_CASE_MERMAID = "safety-case.mermaid";

    /** The six GSN Community Standard node types (§9.2). */
    public static final Set<String> NODE_TYPES =
            Set.of("goal", "strategy", "solution", "context", "assumption", "justification");
    /** The two GSN edge types (§9.2). */
    public static final Set<String> EDGE_TYPES = Set.of("supportedBy", "inContextOf");

    private SafetyCase() {}

    public record Node(String id, String type, String text, String evidence) {}

    public record Edge(String from, String to, String type) {}

    public record Completeness(int totalGoals, int goalsWithEvidence, int undeveloped) {}

    public record SafetyCaseReport(List<Node> nodes, List<Edge> edges, Completeness completeness,
                                    Attestation attestation) {}

    /** One top-level claim and the evidence artefact(s) that would substantiate it. */
    private record ClaimSpec(String id, String title, String[] evidenceFiles) {}

    private static List<ClaimSpec> claims() {
        return List.of(
                new ClaimSpec("C-001", "tool qualification evidence is available",
                        new String[]{"qualify-report.json"}),
                new ClaimSpec("C-002", "requirements are registered and traceable",
                        new String[]{".fusa-reqs.json"}),
                new ClaimSpec("C-003", "a Software Bill of Materials is complete",
                        new String[]{"sbom.json"}),
                new ClaimSpec("C-004", "build provenance and artefact integrity are established",
                        new String[]{"provenance.json", "artifact-manifest.json"}),
                new ClaimSpec("C-005", "hazards are analyzed and traced to safety goals",
                        new String[]{".fusa-hara.json"}),
                new ClaimSpec("C-006", "cybersecurity threats are analyzed and treated",
                        new String[]{"tara.json"}),
                new ClaimSpec("C-007", "failure modes and effects are analyzed",
                        new String[]{"fmea.json"}),
                new ClaimSpec("C-008", "audit evidence is bundled for independent review",
                        new String[]{"audit-pack.zip"})
        );
    }

    // ── Build — project evidence into a GSN graph ─────────────────────────────

    //fusa:req REQ-SAFETYCASE001
    public static SafetyCaseReport build(Path root, String project, String standard) throws IOException {
        List<Node> nodes = new ArrayList<>();
        List<Edge> edges = new ArrayList<>();
        int totalGoals = 0, goalsWithEvidence = 0, undeveloped = 0;

        for (ClaimSpec c : claims()) {
            totalGoals++;
            String goalId = c.id();
            String strategyId = c.id() + "-St";
            nodes.add(new Node(goalId, "goal",
                    project + " demonstrates that " + c.title() + " (standard: " + standard + ")", null));
            nodes.add(new Node(strategyId, "strategy",
                    "Argument by inspection of " + String.join(", ", c.evidenceFiles())
                            + " for " + project, null));
            edges.add(new Edge(goalId, strategyId, "supportedBy"));

            boolean hasEvidence = false;
            int sn = 1;
            for (String file : c.evidenceFiles()) {
                if (!Files.exists(root.resolve(file))) continue;
                hasEvidence = true;
                String solutionId = c.id() + "-Sn" + sn++;
                nodes.add(new Node(solutionId, "solution",
                        c.id() + " evidence: " + file + " is present for " + project, file));
                edges.add(new Edge(strategyId, solutionId, "supportedBy"));
            }
            if (hasEvidence) goalsWithEvidence++; else undeveloped++;
        }

        Completeness completeness = new Completeness(totalGoals, goalsWithEvidence, undeveloped);
        Attestation existing = loadExistingAttestation(root);
        return new SafetyCaseReport(nodes, edges, completeness, existing);
    }

    static Attestation loadExistingAttestation(Path root) throws IOException {
        Path f = root.resolve(SAFETY_CASE_JSON);
        if (!Files.exists(f)) return null;
        try {
            return Attestation.fromJson(Json.parseObject(Files.readString(f)));
        } catch (Json.JsonParseException e) {
            return null;
        }
    }

    // ── Content-quality baseline (§1.6/§1.6.1) ────────────────────────────────

    /** A safety-case node's {@code text} is the field §1.6.1 names directly for this artifact. */
    //fusa:req REQ-SAFETYCASE007
    public static List<QualityBar.Field> qualityBarFields(List<Node> nodes) {
        List<QualityBar.Field> fields = new ArrayList<>();
        for (Node n : nodes) fields.add(new QualityBar.Field(n.id(), "text", n.text()));
        return fields;
    }

    //fusa:req REQ-SAFETYCASE007
    public static Map<String, Object> substantiveContent(List<Node> nodes, List<Edge> edges) {
        Map<String, Object> m = new LinkedHashMap<>();
        List<Object> nodeMaps = new ArrayList<>();
        for (Node n : nodes) {
            Map<String, Object> nm = new LinkedHashMap<>();
            nm.put("id", n.id());
            nm.put("type", n.type());
            nm.put("text", n.text());
            if (n.evidence() != null) nm.put("evidence", n.evidence());
            nodeMaps.add(nm);
        }
        List<Object> edgeMaps = new ArrayList<>();
        for (Edge e : edges) {
            Map<String, Object> em = new LinkedHashMap<>();
            em.put("from", e.from());
            em.put("to", e.to());
            em.put("type", e.type());
            edgeMaps.add(em);
        }
        m.put("nodes", nodeMaps);
        m.put("edges", edgeMaps);
        return m;
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    //fusa:req REQ-SAFETYCASE002
    public static void writeJson(Path root, SafetyCaseReport report, String outputFile) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "safety-case");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        Map<String, Object> content = substantiveContent(report.nodes(), report.edges());
        w.key("nodes"); w.rawValue(content.get("nodes"));
        w.key("edges"); w.rawValue(content.get("edges"));
        w.key("completeness"); w.objectStart();
        w.field("totalGoals", report.completeness().totalGoals());
        w.field("goalsWithEvidence", report.completeness().goalsWithEvidence());
        w.field("undeveloped", report.completeness().undeveloped());
        w.objectEnd();
        if (report.attestation() != null) report.attestation().writeJson(w);
        w.objectEnd();
        String path = (outputFile == null || outputFile.isBlank()) ? SAFETY_CASE_JSON : outputFile;
        Files.writeString(root.resolve(path), w.toPretty() + "\n");
    }

    //fusa:req REQ-SAFETYCASE002
    public static void writeMarkdown(Path root, SafetyCaseReport report, String project, String standard)
            throws IOException {
        var sb = new StringBuilder();
        sb.append("# Safety Case — ").append(project).append("\n\n");
        sb.append("**Standard:** ").append(standard).append("  \n");
        sb.append("**Generated:** ").append(Instant.now()).append("\n\n");
        sb.append("## GSN Argument\n\n");
        sb.append("| ID | Type | Text | Evidence |\n|---|---|---|---|\n");
        for (Node n : report.nodes()) {
            sb.append("| ").append(n.id()).append(" | ").append(n.type()).append(" | ").append(n.text())
                    .append(" | ").append(n.evidence() == null ? "" : n.evidence()).append(" |\n");
        }
        sb.append("\n## Completeness\n\n");
        sb.append("- Total goals: **").append(report.completeness().totalGoals()).append("**\n");
        sb.append("- Goals with evidence: **").append(report.completeness().goalsWithEvidence()).append("**\n");
        sb.append("- Undeveloped: **").append(report.completeness().undeveloped()).append("**\n");
        Files.writeString(root.resolve(SAFETY_CASE_MD), sb.toString());
    }

    //fusa:req REQ-SAFETYCASE002
    public static void writeMermaid(Path root, SafetyCaseReport report) throws IOException {
        var sb = new StringBuilder("graph TD\n");
        for (Node n : report.nodes()) {
            sb.append("    ").append(mermaidId(n.id())).append("[\"").append(n.id()).append(": ")
                    .append(escapeMermaid(n.text())).append("\"]\n");
        }
        for (Edge e : report.edges()) {
            sb.append("    ").append(mermaidId(e.from())).append(" --> ").append(mermaidId(e.to())).append('\n');
        }
        Files.writeString(root.resolve(SAFETY_CASE_MERMAID), sb.toString());
    }

    private static String mermaidId(String id) { return id.replaceAll("[^A-Za-z0-9]", "_"); }

    private static String escapeMermaid(String s) { return s.replace("\"", "'"); }

    // ── Text rendering ────────────────────────────────────────────────────────

    //fusa:req REQ-SAFETYCASE003
    public static String renderText(SafetyCaseReport report, String project, String standard) {
        var sb = new StringBuilder();
        sb.append("Safety Case — ").append(project).append(" (").append(standard).append(")\n\n");
        for (Node n : report.nodes()) {
            sb.append('[').append(n.type()).append("] ").append(n.id()).append(": ").append(n.text());
            if (n.evidence() != null) sb.append("  (evidence: ").append(n.evidence()).append(')');
            sb.append('\n');
        }
        sb.append("\nCompleteness: ").append(report.completeness().goalsWithEvidence()).append('/')
                .append(report.completeness().totalGoals()).append(" goals have evidence, ")
                .append(report.completeness().undeveloped()).append(" undeveloped\n");
        return sb.toString();
    }
}
