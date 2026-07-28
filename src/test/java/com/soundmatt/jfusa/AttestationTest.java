package com.soundmatt.jfusa;

import com.soundmatt.jfusa.attestation.Attestation;
import com.soundmatt.jfusa.internal.CanonJson;
import com.soundmatt.jfusa.internal.Json;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AttestationTest {

    @Test
    //fusa:test REQ-ATT001
    void unrecognisedStatus_isTreatedAsHeuristic_failSafe() {
        Attestation a = new Attestation("bogus", "auto", "", "", "");
        assertFalse(a.isReviewed());
        assertEquals(Attestation.HEURISTIC, a.status());
    }

    @Test
    //fusa:test REQ-ATT001
    void reviewedStatus_isRecognised() {
        Attestation a = new Attestation("reviewed", "auto", "Jane Doe", "2026-07-28T00:00:00Z", "sha256:x");
        assertTrue(a.isReviewed());
    }

    @Test
    //fusa:test REQ-ATT002
    void independence_requiresDifferentReviewer() {
        Attestation self = new Attestation("reviewed", "Alice", "Alice", "2026-07-28T00:00:00Z", "sha256:x");
        assertFalse(self.isIndependent(), "a self-attestation must not count as independent");

        Attestation other = new Attestation("reviewed", "Alice", "Bob", "2026-07-28T00:00:00Z", "sha256:x");
        assertTrue(other.isIndependent());
    }

    @Test
    //fusa:test REQ-ATT002
    void independence_blankReviewer_isNotIndependent() {
        Attestation a = new Attestation("reviewed", "Alice", "", "2026-07-28T00:00:00Z", "sha256:x");
        assertFalse(a.isIndependent());
    }

    @Test
    //fusa:test REQ-ATT003
    void isFresh_matchesRecomputedHash() {
        Object content = Map.of("entries", List.of("a", "b"));
        String hash = CanonJson.sha256Prefixed(content);
        Attestation a = new Attestation("reviewed", "Alice", "Bob", "2026-07-28T00:00:00Z", hash);
        assertTrue(a.isFresh(content));
    }

    @Test
    //fusa:test REQ-ATT003
    void isFresh_isStaleWhenContentChanged() {
        Object originalContent = Map.of("entries", List.of("a", "b"));
        String hash = CanonJson.sha256Prefixed(originalContent);
        Attestation a = new Attestation("reviewed", "Alice", "Bob", "2026-07-28T00:00:00Z", hash);
        Object changedContent = Map.of("entries", List.of("a", "b", "c"));
        assertFalse(a.isFresh(changedContent));
    }

    @Test
    //fusa:test REQ-ATT003
    void isFresh_falseWhenHeuristicOrHashBlank() {
        Attestation heuristic = new Attestation("heuristic", "auto", "", "", "");
        assertFalse(heuristic.isFresh(Map.of("a", 1L)));
        Attestation noHash = new Attestation("reviewed", "Alice", "Bob", "2026-07-28T00:00:00Z", "");
        assertFalse(noHash.isFresh(Map.of("a", 1L)));
    }

    @Test
    //fusa:test REQ-ATT004
    void suppressesRuleB_onlyWhenIndependentAndFresh() {
        Object content = Map.of("a", 1L);
        String hash = CanonJson.sha256Prefixed(content);
        Attestation valid = new Attestation("reviewed", "Alice", "Bob", "2026-07-28T00:00:00Z", hash);
        assertTrue(valid.suppressesRuleB(content));

        Attestation selfReview = new Attestation("reviewed", "Alice", "Alice", "2026-07-28T00:00:00Z", hash);
        assertFalse(selfReview.suppressesRuleB(content));

        Attestation stale = new Attestation("reviewed", "Alice", "Bob", "2026-07-28T00:00:00Z", hash);
        assertFalse(stale.suppressesRuleB(Map.of("a", 2L)));
    }

    @Test
    //fusa:test REQ-ATT005
    void fromJson_returnsNullWhenAbsentOrEmpty() {
        assertNull(Attestation.fromJson(null));
        assertNull(Attestation.fromJson(Json.parseObject("{}")));
        assertNull(Attestation.fromJson(Json.parseObject("{\"attestation\":{}}")));
    }

    @Test
    //fusa:test REQ-ATT005
    void fromJson_andWriteJson_roundTrip() {
        Map<String, Object> doc = Json.parseObject("""
                {"attestation": {"status":"reviewed","implementationAuthor":"auto",
                 "independentReviewer":"Jane Doe","reviewedAt":"2026-07-28T00:00:00Z",
                 "contentHash":"sha256:abc"}}
                """);
        Attestation a = Attestation.fromJson(doc);
        assertNotNull(a);
        assertEquals("reviewed", a.status());
        assertEquals("Jane Doe", a.independentReviewer());
        assertEquals("sha256:abc", a.contentHash());

        var w = new Json.Writer();
        w.objectStart();
        a.writeJson(w);
        w.objectEnd();
        String out = w.toString();
        assertTrue(out.contains("\"independentReviewer\":\"Jane Doe\""));
        assertTrue(out.contains("\"status\":\"reviewed\""));
    }
}
