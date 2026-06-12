package com.soundmatt.jfusa;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class FuSaTest {

    @Test
    void severityRank() {
        assertTrue(FuSa.Severity.ERROR.rank() > FuSa.Severity.WARNING.rank());
        assertTrue(FuSa.Severity.WARNING.rank() > FuSa.Severity.INFO.rank());
    }

    @Test
    void categoryJsonValue() {
        assertEquals("supply-chain", FuSa.Category.SUPPLY_CHAIN.jsonValue());
        assertEquals("safety", FuSa.Category.safety.jsonValue());
        assertEquals("other", FuSa.Category.other.jsonValue());
    }

    @Test
    void deriveCategoryPrefix() {
        assertEquals(FuSa.Category.safety,    FuSa.deriveCategory("FUSA001"));
        assertEquals(FuSa.Category.lint,      FuSa.deriveCategory("LINT005"));
        assertEquals(FuSa.Category.security,  FuSa.deriveCategory("CYBER010"));
        assertEquals(FuSa.Category.other,     FuSa.deriveCategory("UNKNOWN42"));
    }

    @Test
    void normalizeMessage() {
        assertEquals("line # has # items",
                FuSa.normalizeMessage("line 42 has 7 items"));
        assertEquals("error at col #", FuSa.normalizeMessage("error at col 12"));
        assertEquals("no digits", FuSa.normalizeMessage("no digits"));
    }

    @Test
    void computeFingerprint_deterministic() {
        FuSa.Finding a = FuSa.Finding.builder("LINT001", FuSa.Severity.WARNING,
                "return null without //fusa:unsafe",
                new FuSa.Location("Foo.java", 10)).build();
        FuSa.Finding b = FuSa.Finding.builder("LINT001", FuSa.Severity.WARNING,
                "return null without //fusa:unsafe",
                new FuSa.Location("Foo.java", 10)).build();
        assertEquals(a.fingerprint(), b.fingerprint());
        assertFalse(a.fingerprint().isBlank());
    }

    @Test
    void computeFingerprint_differs_for_different_messages() {
        FuSa.Finding a = FuSa.Finding.builder("LINT001", FuSa.Severity.WARNING,
                "message A", new FuSa.Location("X.java", 1)).build();
        FuSa.Finding b = FuSa.Finding.builder("LINT001", FuSa.Severity.WARNING,
                "message B", new FuSa.Location("X.java", 1)).build();
        assertNotEquals(a.fingerprint(), b.fingerprint());
    }

    @Test
    void computeFingerprint_stable_across_line_numbers() {
        // Fingerprint uses ruleId + file + normalizedMessage — NOT line number
        FuSa.Finding a = FuSa.Finding.builder("LINT001", FuSa.Severity.WARNING,
                "return null without //fusa:unsafe",
                new FuSa.Location("Foo.java", 10)).build();
        FuSa.Finding b = FuSa.Finding.builder("LINT001", FuSa.Severity.WARNING,
                "return null without //fusa:unsafe",
                new FuSa.Location("Foo.java", 20)).build();
        assertEquals(a.fingerprint(), b.fingerprint());
    }

    @Test
    void findingBuilder_setsFields() {
        FuSa.Finding f = FuSa.Finding.builder("ANA001", FuSa.Severity.ERROR,
                "chained call without null check",
                new FuSa.Location("Bar.java", 5))
                .category(FuSa.Category.safety)
                .standard("IEC 61508").clause("7.4.3")
                .remediation("add null guard")
                .build();
        assertEquals("ANA001", f.ruleId());
        assertEquals(FuSa.Severity.ERROR, f.severity());
        assertEquals("Bar.java", f.location().file());
        assertEquals(5, f.location().line());
        assertEquals(FuSa.Category.safety, f.category());
        assertEquals("IEC 61508", f.standard());
        assertEquals("7.4.3", f.clause());
        assertEquals("add null guard", f.remediation());
        assertFalse(f.fingerprint().isBlank());
    }

    @Test
    void locationConvenienceConstructor() {
        FuSa.Location l = new FuSa.Location("Foo.java", 42);
        assertEquals("Foo.java", l.file());
        assertEquals(42, l.line());
        assertEquals(0, l.column());
    }

    @Test
    void exitCodesDistinct() {
        int[] codes = {FuSa.EXIT_OK, FuSa.EXIT_GATE_FAIL, FuSa.EXIT_USAGE, FuSa.EXIT_RUNTIME};
        long distinct = java.util.Arrays.stream(codes).distinct().count();
        assertEquals(4, distinct);
    }
}
