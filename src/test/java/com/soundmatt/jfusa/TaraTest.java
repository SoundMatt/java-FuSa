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
        var ir = new Tara.ImpactRating("negligible", "critical", "moderate", "negligible");
        assertEquals("critical", Tara.highestImpact(ir));
    }

    @Test
    //fusa:test REQ-TARA006
    void deriveRisk_criticalImpactHighFeasibility_isCritical() {
        var ir = new Tara.ImpactRating("critical", "negligible", "negligible", "negligible");
        assertEquals("critical", Tara.deriveRisk(ir, "high"));
    }

    @Test
    //fusa:test REQ-TARA006
    void deriveRisk_negligibleImpactLowFeasibility_isLow() {
        var ir = new Tara.ImpactRating("negligible", "negligible", "negligible", "negligible");
        assertEquals("low", Tara.deriveRisk(ir, "low"));
    }

    /**
     * Regression test for x-FuSa/java-FuSa#34: {@code deriveRisk} must implement the x-FuSa spec
     * §9.2 risk-combination table verbatim across all 16 impact×feasibility cells, using the
     * spec-mandated {@code critical|major|moderate|negligible} impact vocabulary — not just the
     * subset of cells the tool's own fixed catalogue happens to exercise.
     */
    @Test
    //fusa:test REQ-TARA006
    void deriveRisk_matchesSpecCombinationTableForAll16Cells() {
        String[] impacts = {"negligible", "moderate", "major", "critical"};
        String[] feasibilities = {"very-low", "low", "medium", "high"};
        String[][] expected = {
                // very-low,  low,      medium,     high
                { "low",      "low",    "low",      "low"      }, // negligible
                { "low",      "low",    "medium",   "medium"   }, // moderate
                { "medium",   "medium", "high",     "high"     }, // major
                { "medium",   "high",   "critical", "critical" }, // critical
        };
        for (int i = 0; i < impacts.length; i++) {
            for (int f = 0; f < feasibilities.length; f++) {
                var ir = new Tara.ImpactRating(impacts[i], "negligible", "negligible", "negligible");
                assertEquals(expected[i][f], Tara.deriveRisk(ir, feasibilities[f]),
                        "impact=" + impacts[i] + " feasibility=" + feasibilities[f]);
            }
        }
    }

    @Test
    //fusa:test REQ-TARA006
    void deriveRisk_rejectsHighMediumLowVocabularyForImpactAxes() {
        // §9.2 closed enum: impact.{safety,financial,operational,privacy} MUST use
        // critical|major|moderate|negligible, never attackFeasibility's high|medium|low vocabulary.
        // An unrecognised value (including the disallowed vocabulary) falls back to the lowest
        // rank (negligible) — fail-safe, never silently promoted to a higher risk than warranted,
        // but also never silently downgraded from what a spec-correct "major" would have produced.
        var majorEquivalentButWrongVocab = new Tara.ImpactRating("high", "negligible", "negligible", "negligible");
        var majorSpecVocab = new Tara.ImpactRating("major", "negligible", "negligible", "negligible");
        assertEquals("low", Tara.deriveRisk(majorEquivalentButWrongVocab, "high"),
                "the disallowed high|medium|low vocabulary must not be silently accepted as impact");
        assertEquals("high", Tara.deriveRisk(majorSpecVocab, "high"),
                "the spec-correct 'major' vocabulary must be recognised");
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
