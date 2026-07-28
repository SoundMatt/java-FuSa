package com.soundmatt.jfusa;

import com.soundmatt.jfusa.attestation.Attestation;
import com.soundmatt.jfusa.disposition.Disposition;
import com.soundmatt.jfusa.internal.CanonJson;
import com.soundmatt.jfusa.qualitybar.QualityBar;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class QualityBarTest {

    @TempDir Path tmp;

    // ── Rule A — FUSA-STUB001 ─────────────────────────────────────────────────

    @Test
    //fusa:test REQ-QB001
    void scanPlaceholders_flagsBracketedInstructionalText() {
        var fields = List.of(new QualityBar.Field("E-001", "hazard", "[describe hazard]"));
        var findings = QualityBar.scanPlaceholders("fmea.json", fields);
        assertEquals(1, findings.size());
        assertEquals(QualityBar.STUB001, findings.get(0).ruleId());
        assertEquals(FuSa.Severity.ERROR, findings.get(0).severity());
    }

    @Test
    //fusa:test REQ-QB001
    void scanPlaceholders_flagsDenylistPhrasesCaseInsensitively() {
        var fields = List.of(
                new QualityBar.Field("E-001", "hazard", "Example hazard — REPLACE WITH real content"),
                new QualityBar.Field("E-002", "hazard", "TBD"),
                new QualityBar.Field("E-003", "hazard", "lorem ipsum dolor"),
                new QualityBar.Field("E-004", "hazard", "fill in the details"));
        var findings = QualityBar.scanPlaceholders("fmea.json", fields);
        assertEquals(4, findings.size());
        assertTrue(findings.stream().allMatch(f -> f.ruleId().equals(QualityBar.STUB001)));
    }

    @Test
    //fusa:test REQ-QB001
    void scanPlaceholders_realContentIsClean() {
        var fields = List.of(new QualityBar.Field("E-001", "hazard",
                "Loss of braking torque during regenerative braking transition"));
        assertTrue(QualityBar.scanPlaceholders("fmea.json", fields).isEmpty());
    }

    // ── Rule B — FUSA-STUB002 ─────────────────────────────────────────────────

    @Test
    //fusa:test REQ-QB002
    void scanBlanketFallback_flagsRepeatedValueAcrossTenPlusEntries() {
        List<QualityBar.Field> fields = new ArrayList<>();
        for (int i = 0; i < 12; i++) fields.add(new QualityBar.Field("E-" + i, "failureMode", "same text every time"));
        var findings = QualityBar.scanBlanketFallback("fmea.json", fields);
        assertEquals(1, findings.size());
        assertEquals(QualityBar.STUB002, findings.get(0).ruleId());
        assertEquals(FuSa.Severity.WARNING, findings.get(0).severity());
    }

    @Test
    //fusa:test REQ-QB002
    void scanBlanketFallback_belowTenEntries_neverFlagged() {
        List<QualityBar.Field> fields = new ArrayList<>();
        for (int i = 0; i < 9; i++) fields.add(new QualityBar.Field("E-" + i, "failureMode", "same text"));
        assertTrue(QualityBar.scanBlanketFallback("fmea.json", fields).isEmpty());
    }

    @Test
    //fusa:test REQ-QB002
    void scanBlanketFallback_sufficientlyDistinctValues_notFlagged() {
        List<QualityBar.Field> fields = new ArrayList<>();
        for (int i = 0; i < 12; i++) fields.add(new QualityBar.Field("E-" + i, "failureMode", "distinct value " + i));
        assertTrue(QualityBar.scanBlanketFallback("fmea.json", fields).isEmpty());
    }

    @Test
    //fusa:test REQ-QB002
    void distinctValueRatio_computesCorrectly() {
        assertEquals(1.0, QualityBar.distinctValueRatio(List.of()));
        assertEquals(0.5, QualityBar.distinctValueRatio(List.of("a", "a", "b", "b")));
        assertEquals(1.0, QualityBar.distinctValueRatio(List.of("a", "b", "c")));
    }

    // ── Disposition suppression ───────────────────────────────────────────────

    @Test
    //fusa:test REQ-QB003
    void isDispositioned_acceptedEntrySuppresses() throws Exception {
        Disposition.add(tmp, QualityBar.STUB001, "fmea.json", "accepted", "false positive, reviewed");
        assertTrue(QualityBar.isDispositioned(tmp, QualityBar.STUB001, "fmea.json"));
    }

    @Test
    //fusa:test REQ-QB003
    void isDispositioned_rejectedEntryDoesNotSuppress() throws Exception {
        Disposition.add(tmp, QualityBar.STUB001, "fmea.json", "rejected", "waiver denied");
        assertFalse(QualityBar.isDispositioned(tmp, QualityBar.STUB001, "fmea.json"));
    }

    @Test
    //fusa:test REQ-QB003
    void isDispositioned_noEntry_doesNotSuppress() throws Exception {
        assertFalse(QualityBar.isDispositioned(tmp, QualityBar.STUB001, "fmea.json"));
    }

    @Test
    //fusa:test REQ-QB003
    void isDispositioned_differentFile_doesNotSuppress() throws Exception {
        Disposition.add(tmp, QualityBar.STUB001, "tara.json", "accepted", "n/a");
        assertFalse(QualityBar.isDispositioned(tmp, QualityBar.STUB001, "fmea.json"));
    }

    // ── Combined evaluation ───────────────────────────────────────────────────

    @Test
    //fusa:test REQ-QB004
    void evaluate_ruleA_blocksUnlessDispositioned() throws Exception {
        var fields = List.of(new QualityBar.Field("E-001", "hazard", "TBD"));
        QualityBar.Result r = QualityBar.evaluate(tmp, "fmea.json", fields, null, Map.of());
        assertTrue(r.hasBlockingError());

        Disposition.add(tmp, QualityBar.STUB001, "fmea.json", "accepted", "waived");
        QualityBar.Result r2 = QualityBar.evaluate(tmp, "fmea.json", fields, null, Map.of());
        assertFalse(r2.hasBlockingError());
        assertEquals(FuSa.Disposition.accepted, r2.findings().get(0).disposition());
    }

    @Test
    //fusa:test REQ-QB004
    void evaluate_ruleB_suppressedOnlyByValidAttestation() throws Exception {
        List<QualityBar.Field> fields = new ArrayList<>();
        for (int i = 0; i < 12; i++) fields.add(new QualityBar.Field("E-" + i, "failureMode", "same text"));
        Object content = List.of(Map.of("a", 1L));

        QualityBar.Result noAttestation = QualityBar.evaluate(tmp, "fmea.json", fields, null, content);
        assertTrue(noAttestation.hasUnsuppressedWarning());

        String hash = CanonJson.sha256Prefixed(content);
        Attestation valid = new Attestation("reviewed", "auto", "Jane Doe", "2026-07-28T00:00:00Z", hash);
        QualityBar.Result suppressed = QualityBar.evaluate(tmp, "fmea.json", fields, valid, content);
        assertFalse(suppressed.hasUnsuppressedWarning());
        assertFalse(suppressed.hasBlockingError());

        Attestation selfReview = new Attestation("reviewed", "auto", "auto", "2026-07-28T00:00:00Z", hash);
        QualityBar.Result stillWarns = QualityBar.evaluate(tmp, "fmea.json", fields, selfReview, content);
        assertTrue(stillWarns.hasUnsuppressedWarning(), "a self-attestation must not suppress rule B");
    }

    @Test
    //fusa:test REQ-QB004
    void renderText_emptyWhenNoFindings() {
        assertEquals("", QualityBar.renderText(new QualityBar.Result(List.of(), false, false)));
    }
}
