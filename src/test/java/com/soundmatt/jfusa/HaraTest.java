package com.soundmatt.jfusa;

import com.soundmatt.jfusa.hara.Hara;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class HaraTest {

    @TempDir Path tmp;

    // ── deriveAsil() — ISO 26262-3 Table 4 ────────────────────────────────────

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_severityZero_isAlwaysQM() {
        assertEquals("QM", Hara.deriveAsil(0, 1, 1));
        assertEquals("QM", Hara.deriveAsil(0, 4, 3));
    }

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_severityTwo_lowExposure_isQM() {
        assertEquals("QM", Hara.deriveAsil(2, 1, 3));
    }

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_severityTwo_highExposureHighControllability_isC() {
        // s=2, e=3, c=3 -> ASIL-C (ISO 26262-3:2018 Table 4)
        assertEquals("ASIL-C", Hara.deriveAsil(2, 3, 3));
    }

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_severityThree_exposureThreeControllabilityTwo_isD() {
        // s=3, e=3, c=2 -> ASIL-D (ISO 26262-3:2018 Table 4)
        assertEquals("ASIL-D", Hara.deriveAsil(3, 3, 2));
    }

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_severityThree_highestExposureAndControllability_isD() {
        // s=3, e>=4, c==2 -> ASIL-D
        assertEquals("ASIL-D", Hara.deriveAsil(3, 4, 2));
    }

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_stringOverload_parsesLetterDigitForm() {
        assertEquals("ASIL-D", Hara.deriveAsil("S3", "E3", "C2"));
        assertEquals("QM", Hara.deriveAsil("S0", "E4", "C3"));
    }

    // ── init() ─────────────────────────────────────────────────────────────────

    //fusa:test REQ-HARA002
    @Test
    void init_writesHaraFile() throws Exception {
        Hara.init(tmp, "hara-test", "iso26262");
        assertTrue(Files.exists(tmp.resolve(Hara.HARA_FILE)));
    }

    //fusa:test REQ-HARA002
    @Test
    void init_scaffoldsEmptyCollections_neverDummyRows() throws Exception {
        Hara.init(tmp, "hara-test", "iso26262");
        Hara.HaraDoc doc = Hara.load(tmp);
        assertTrue(doc.situations().isEmpty());
        assertTrue(doc.hazards().isEmpty());
        assertTrue(doc.safetyGoals().isEmpty());
    }

    //fusa:test REQ-HARA002
    @Test
    void init_doesNotOverwriteExisting() throws Exception {
        Hara.init(tmp, "hara-test", "iso26262");
        String before = Files.readString(tmp.resolve(Hara.HARA_FILE));
        Hara.init(tmp, "different-name", "iso26262");
        String after = Files.readString(tmp.resolve(Hara.HARA_FILE));
        assertEquals(before, after, "init() must not overwrite an existing .fusa-hara.json");
    }

    // ── load() / validate() / computeCompleteness() ───────────────────────────

    //fusa:test REQ-HARA003
    @Test
    void load_withoutFile_returnsEmptyDoc() throws Exception {
        Hara.HaraDoc doc = Hara.load(tmp);
        assertTrue(doc.hazards().isEmpty());
        assertTrue(doc.safetyGoals().isEmpty());
    }

    //fusa:test REQ-HARA004
    @Test
    void validate_flagsSafetyGoalWithoutFssrRefs() {
        var goal = new Hara.SafetyGoal("SG-001", "Safety output must remain within safe bounds",
                List.of("H-001"), "ASIL-C", "", List.of());
        var risk = new Hara.RiskRating("S3", "E3", "C2", "ASIL-C");
        var hazard = new Hara.Hazard("H-001", "Incorrect safety-critical output under load", "review",
                List.of(), risk, List.of("SG-001"));
        var doc = new Hara.HaraDoc("proj", "iso26262", "", List.of(), List.of(hazard), List.of(goal), null);
        List<Hara.ValidationFinding> findings = Hara.validate(doc, Set.of());
        assertTrue(findings.stream().anyMatch(f -> f.message().contains("no fssrRefs")));
    }

    //fusa:test REQ-HARA004
    @Test
    void validate_flagsDanglingFssrRef() {
        var goal = new Hara.SafetyGoal("SG-001", "desc", List.of("H-001"), "ASIL-C", "", List.of("REQ-MISSING"));
        var risk = new Hara.RiskRating("S3", "E3", "C2", "ASIL-C");
        var hazard = new Hara.Hazard("H-001", "desc", "", List.of(), risk, List.of("SG-001"));
        var doc = new Hara.HaraDoc("proj", "iso26262", "", List.of(), List.of(hazard), List.of(goal), null);
        List<Hara.ValidationFinding> findings = Hara.validate(doc, Set.of("REQ-OTHER"));
        assertTrue(findings.stream().anyMatch(f -> f.message().contains("REQ-MISSING")));
    }

    //fusa:test REQ-HARA005
    @Test
    void computeCompleteness_countsFssrRefsAndDangling() {
        var goalOk = new Hara.SafetyGoal("SG-001", "desc", List.of("H-001"), "ASIL-C", "", List.of("REQ-001"));
        var goalGap = new Hara.SafetyGoal("SG-002", "desc", List.of("H-002"), "ASIL-B", "", List.of());
        var risk = new Hara.RiskRating("S3", "E3", "C2", "ASIL-C");
        var hazard1 = new Hara.Hazard("H-001", "desc", "", List.of(), risk, List.of("SG-001"));
        var hazard2 = new Hara.Hazard("H-002", "desc", "", List.of(), risk, List.of("SG-002"));
        var doc = new Hara.HaraDoc("proj", "iso26262", "", List.of(), List.of(hazard1, hazard2),
                List.of(goalOk, goalGap), null);
        Hara.Completeness c = Hara.computeCompleteness(doc, Set.of("REQ-001"));
        assertEquals(2, c.totalHazards());
        assertEquals(2, c.totalSafetyGoals());
        assertEquals(1, c.safetyGoalsWithFssrRefs());
        assertEquals(0, c.danglingReferences());
    }

    //fusa:test REQ-HARA003
    @Test
    void loadReqIds_readsIdsFromReqsFile() throws Exception {
        Files.writeString(tmp.resolve(".fusa-reqs.json"),
                "{\"schema\":\"x-fusa-reqs-1.0\",\"requirements\":[{\"id\":\"REQ-FOO001\",\"title\":\"x\"}]}");
        Set<String> ids = Hara.loadReqIds(tmp);
        assertEquals(Set.of("REQ-FOO001"), ids);
    }

    //fusa:test REQ-HARA003
    @Test
    void loadReqIds_absentFile_returnsEmptySet() throws Exception {
        assertTrue(Hara.loadReqIds(tmp).isEmpty());
    }

    //fusa:test REQ-HARA004
    @Test
    void effectiveAsil_nonIso26262Standard_passesThroughGivenValue() {
        var risk = new Hara.RiskRating("S3", "E3", "C2", "ASIL-B");
        assertEquals("ASIL-B", Hara.effectiveAsil("generic", risk));
    }

    //fusa:test REQ-HARA006
    @Test
    void qualityBarFields_coverHazardAndSafetyGoalDescriptions() {
        var goal = new Hara.SafetyGoal("SG-001", "goal desc", List.of("H-001"), "ASIL-C", "", List.of("REQ-001"));
        var risk = new Hara.RiskRating("S3", "E3", "C2", "ASIL-C");
        var hazard = new Hara.Hazard("H-001", "hazard desc", "", List.of(), risk, List.of("SG-001"));
        var doc = new Hara.HaraDoc("proj", "iso26262", "", List.of(), List.of(hazard), List.of(goal), null);
        var fields = Hara.qualityBarFields(doc);
        assertEquals(2, fields.size());
        assertTrue(fields.stream().anyMatch(f -> f.value().equals("hazard desc")));
        assertTrue(fields.stream().anyMatch(f -> f.value().equals("goal desc")));
    }

    //fusa:test REQ-HARA007
    @Test
    void renderText_listsHazardsSafetyGoalsAndFindings() {
        var goal = new Hara.SafetyGoal("SG-001", "goal desc", List.of("H-001"), "ASIL-C", "", List.of());
        var risk = new Hara.RiskRating("S3", "E3", "C2", "");
        var hazard = new Hara.Hazard("H-001", "hazard desc", "", List.of(), risk, List.of("SG-001"));
        var doc = new Hara.HaraDoc("proj", "iso26262", "", List.of(), List.of(hazard), List.of(goal), null);
        List<Hara.ValidationFinding> findings = Hara.validate(doc, Set.of());
        Hara.Completeness c = Hara.computeCompleteness(doc, Set.of());
        String text = Hara.renderText(doc, findings, c);
        assertTrue(text.contains("HARA"));
        assertTrue(text.contains("H-001"));
        assertTrue(text.contains("SG-001"));
        assertTrue(text.contains("Validation findings"));
    }

    //fusa:test REQ-HARA004
    @Test
    void validate_flagsHazardWithNoSituationsOrSafetyGoals() {
        var risk = new Hara.RiskRating("", "", "", "");
        var hazard = new Hara.Hazard("H-001", "desc", "", List.of(), risk, List.of());
        var doc = new Hara.HaraDoc("proj", "iso26262", "", List.of(), List.of(hazard), List.of(), null);
        List<Hara.ValidationFinding> findings = Hara.validate(doc, Set.of());
        assertTrue(findings.stream().anyMatch(f -> f.message().contains("incomplete risk rating")));
        assertTrue(findings.stream().anyMatch(f -> f.message().contains("no linked safety goal")));
    }

    //fusa:test REQ-HARA007
    @Test
    void renderJson_includesCompletenessAndDerivedAsil() {
        var goal = new Hara.SafetyGoal("SG-001", "desc", List.of("H-001"), "ASIL-C", "", List.of("REQ-001"));
        var risk = new Hara.RiskRating("S3", "E3", "C2", "");
        var hazard = new Hara.Hazard("H-001", "desc", "", List.of(), risk, List.of("SG-001"));
        var doc = new Hara.HaraDoc("proj", "iso26262", "", List.of(), List.of(hazard), List.of(goal), null);
        Hara.Completeness c = Hara.computeCompleteness(doc, Set.of("REQ-001"));
        String json = Hara.renderJson(doc, c);
        assertTrue(json.contains("\"kind\": \"hara-report\""));
        assertTrue(json.contains("\"completeness\""));
        assertTrue(json.contains("\"ASIL-D\""), "ASIL should be derived from S3/E3/C2 even though risk.asil was blank");
    }
}
