package com.soundmatt.jfusa;

import com.soundmatt.jfusa.safetycase.SafetyCase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SafetyCaseTest {

    @TempDir Path tmp;

    @Test
    //fusa:test REQ-SAFETYCASE001
    void build_withNoEvidencePresent_allGoalsUndeveloped() throws Exception {
        SafetyCase.SafetyCaseReport report = SafetyCase.build(tmp, "proj", "iso26262");
        assertTrue(report.completeness().totalGoals() > 0);
        assertEquals(0, report.completeness().goalsWithEvidence());
        assertEquals(report.completeness().totalGoals(), report.completeness().undeveloped());
    }

    @Test
    //fusa:test REQ-SAFETYCASE001
    void build_onlyEmitsSolutionNodesForEvidenceThatActuallyExists() throws Exception {
        Files.writeString(tmp.resolve("sbom.json"), "{}");
        SafetyCase.SafetyCaseReport report = SafetyCase.build(tmp, "proj", "iso26262");
        assertTrue(report.completeness().goalsWithEvidence() >= 1);
        assertTrue(report.nodes().stream().anyMatch(n -> "solution".equals(n.type()) && "sbom.json".equals(n.evidence())));
    }

    @Test
    //fusa:test REQ-SAFETYCASE001
    void build_everyNodeUsesOneOfTheSixGsnTypes() throws Exception {
        SafetyCase.SafetyCaseReport report = SafetyCase.build(tmp, "proj", "iso26262");
        for (SafetyCase.Node n : report.nodes()) {
            assertTrue(SafetyCase.NODE_TYPES.contains(n.type()), "unexpected node type: " + n.type());
        }
        for (SafetyCase.Edge e : report.edges()) {
            assertTrue(SafetyCase.EDGE_TYPES.contains(e.type()), "unexpected edge type: " + e.type());
        }
    }

    @Test
    //fusa:test REQ-SAFETYCASE007
    void nodeText_isSpecificToProjectNotGenericBoilerplate() throws Exception {
        SafetyCase.SafetyCaseReport report = SafetyCase.build(tmp, "my-unique-project", "iso26262");
        assertTrue(report.nodes().stream().filter(n -> "goal".equals(n.type()))
                .allMatch(n -> n.text().contains("my-unique-project")));
    }

    @Test
    //fusa:test REQ-SAFETYCASE002
    void writeJson_producesNodesEdgesCompleteness() throws Exception {
        SafetyCase.SafetyCaseReport report = SafetyCase.build(tmp, "proj", "iso26262");
        SafetyCase.writeJson(tmp, report, "");
        String json = Files.readString(tmp.resolve(SafetyCase.SAFETY_CASE_JSON));
        assertTrue(json.contains("\"nodes\""));
        assertTrue(json.contains("\"edges\""));
        assertTrue(json.contains("\"completeness\""));
        assertTrue(json.contains("\"kind\": \"safety-case\""));
    }

    @Test
    //fusa:test REQ-SAFETYCASE002
    void writeMermaid_producesGraphDefinition() throws Exception {
        SafetyCase.SafetyCaseReport report = SafetyCase.build(tmp, "proj", "iso26262");
        SafetyCase.writeMermaid(tmp, report);
        String mmd = Files.readString(tmp.resolve(SafetyCase.SAFETY_CASE_MERMAID));
        assertTrue(mmd.startsWith("graph TD"));
    }

    @Test
    //fusa:test REQ-SAFETYCASE003
    void renderText_showsCompletenessSummary() throws Exception {
        SafetyCase.SafetyCaseReport report = SafetyCase.build(tmp, "proj", "iso26262");
        String text = SafetyCase.renderText(report, "proj", "iso26262");
        assertTrue(text.contains("Completeness:"));
    }
}
