package com.soundmatt.jfusa;

import com.soundmatt.jfusa.tara.Tara;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class TaraTest {

    @TempDir Path tmp;

    @Test
    //fusa:test REQ-TARA006
    void highestImpact_returnsWorstCaseAcrossSfopAxes() {
        var ir = new Tara.ImpactRating("low", "critical", "medium", "low");
        assertEquals("critical", Tara.highestImpact(ir));
    }

    @Test
    //fusa:test REQ-TARA006
    void deriveRisk_criticalImpactHighFeasibility_isCritical() {
        var ir = new Tara.ImpactRating("critical", "low", "low", "low");
        assertEquals("critical", Tara.deriveRisk(ir, "high"));
    }

    @Test
    //fusa:test REQ-TARA006
    void deriveRisk_lowImpactLowFeasibility_isLow() {
        var ir = new Tara.ImpactRating("low", "low", "low", "low");
        assertEquals("low", Tara.deriveRisk(ir, "low"));
    }

    @Test
    //fusa:test REQ-TARA002
    void build_producesSfopImpactAndHonestCoverageDisclosure() throws Exception {
        Tara.TaraReport report = Tara.build(tmp, "my-project");
        assertFalse(report.threats().isEmpty());
        for (Tara.ThreatScenario t : report.threats()) {
            assertNotNull(t.impact().safety());
            assertNotNull(t.impact().financial());
            assertNotNull(t.impact().operational());
            assertNotNull(t.impact().privacy());
            assertNotNull(t.risk());
            assertNotNull(t.treatment());
        }
        assertEquals(report.threats().size(), report.summary().assetsAnalyzed());
        assertFalse(report.summary().assetInventoryMethod().isBlank());
    }

    @Test
    //fusa:test REQ-TARA002
    void build_carriesForwardExistingAttestation() throws Exception {
        Files.writeString(tmp.resolve(Tara.TARA_JSON), """
                {"attestation": {"status":"reviewed","implementationAuthor":"auto",
                 "independentReviewer":"Jane Doe","reviewedAt":"2026-07-28T00:00:00Z",
                 "contentHash":"sha256:doesnotmatter"}}
                """);
        Tara.TaraReport report = Tara.build(tmp, "my-project");
        assertNotNull(report.attestation());
        assertEquals("Jane Doe", report.attestation().independentReviewer());
    }

    @Test
    //fusa:test REQ-TARA007
    void qualityBarFields_scansThreatFieldOnly() throws Exception {
        Tara.TaraReport report = Tara.build(tmp, "proj");
        var fields = Tara.qualityBarFields(report.threats());
        assertEquals(report.threats().size(), fields.size());
        assertTrue(fields.stream().allMatch(f -> f.fieldName().equals("threat")));
    }

    @Test
    //fusa:test REQ-TARA003
    void writeJson_respectsCustomOutputPathAndSchema() throws Exception {
        Tara.TaraReport report = Tara.build(tmp, "proj");
        Tara.writeJson(tmp, report, "custom-tara.json");
        assertTrue(Files.exists(tmp.resolve("custom-tara.json")));
        String json = Files.readString(tmp.resolve("custom-tara.json"));
        assertTrue(json.contains("\"threats\""));
        assertTrue(json.contains("\"impact\""));
        assertFalse(json.contains("\"threatScenario\""), "canonical field name is \"threat\", not \"threatScenario\"");
    }

    @Test
    //fusa:test REQ-TARA004
    void renderText_includesImpactAxesAndCoverage() throws Exception {
        Tara.TaraReport report = Tara.build(tmp, "proj");
        String text = Tara.renderText(report);
        assertTrue(text.contains("safety="));
        assertTrue(text.contains("Coverage:"));
    }

    @Test
    //fusa:test REQ-TARA003
    void writeMarkdown_producesTaraMd() throws Exception {
        Tara.TaraReport report = Tara.build(tmp, "proj");
        Tara.writeMarkdown(tmp, report, "proj");
        assertTrue(Files.exists(tmp.resolve(Tara.TARA_MD)));
        String md = Files.readString(tmp.resolve(Tara.TARA_MD));
        assertTrue(md.contains("Threat Catalogue"));
    }
}
