package com.soundmatt.jfusa;

import com.soundmatt.jfusa.internal.CanonJson;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CanonJsonTest {

    @Test
    //fusa:test REQ-CANON001
    void canonicalize_sortsObjectKeys() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("b", 1L);
        m.put("a", 2L);
        assertEquals("{\"a\":2,\"b\":1}", CanonJson.canonicalize(m));
    }

    @Test
    //fusa:test REQ-CANON001
    void canonicalize_isIndependentOfKeyOrder() {
        Map<String, Object> m1 = new LinkedHashMap<>();
        m1.put("x", "1");
        m1.put("y", "2");
        Map<String, Object> m2 = new LinkedHashMap<>();
        m2.put("y", "2");
        m2.put("x", "1");
        assertEquals(CanonJson.canonicalize(m1), CanonJson.canonicalize(m2));
    }

    @Test
    //fusa:test REQ-CANON001
    void canonicalize_isIndependentOfArrayElementKeyOrderWithinEachElement() {
        Map<String, Object> e1 = new LinkedHashMap<>();
        e1.put("id", "A");
        e1.put("val", 1L);
        List<Object> arr = List.of(e1);
        assertEquals("[{\"id\":\"A\",\"val\":1}]", CanonJson.canonicalize(arr));
    }

    @Test
    //fusa:test REQ-CANON001
    void canonicalize_handlesNullBooleanAndNestedStructures() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("n", null);
        m.put("b", true);
        m.put("list", List.of(1L, 2L, 3L));
        assertEquals("{\"b\":true,\"list\":[1,2,3],\"n\":null}", CanonJson.canonicalize(m));
    }

    @Test
    //fusa:test REQ-CANON001
    void canonicalize_integralDoubleHasNoTrailingZero() {
        assertEquals("5", CanonJson.canonicalize(5.0));
        assertEquals("87.5", CanonJson.canonicalize(87.5));
    }

    @Test
    //fusa:test REQ-CANON001
    void canonicalize_escapesStringsLikeJson() {
        assertEquals("\"a\\\"b\\nc\"", CanonJson.canonicalize("a\"b\nc"));
    }

    @Test
    //fusa:test REQ-CANON001
    void canonicalizeJson_matchesCanonicalizeOfParsedValue() {
        String json = "{\"b\":1,\"a\":[true,null]}";
        assertEquals("{\"a\":[true,null],\"b\":1}", CanonJson.canonicalizeJson(json));
    }

    @Test
    //fusa:test REQ-CANON001
    void canonicalize_rejectsUnsupportedType() {
        assertThrows(IllegalArgumentException.class, () -> CanonJson.canonicalize(new Object()));
    }

    @Test
    //fusa:test REQ-CANON002
    void sha256Prefixed_isDeterministicAndPrefixed() {
        String h1 = CanonJson.sha256Prefixed(Map.of("a", 1L));
        String h2 = CanonJson.sha256Prefixed(Map.of("a", 1L));
        assertEquals(h1, h2);
        assertTrue(h1.startsWith("sha256:"));
        assertEquals(71, h1.length()); // "sha256:" + 64 hex chars
    }

    @Test
    //fusa:test REQ-CANON002
    void sha256Prefixed_differsWhenContentDiffers() {
        String h1 = CanonJson.sha256Prefixed(Map.of("a", 1L));
        String h2 = CanonJson.sha256Prefixed(Map.of("a", 2L));
        assertNotEquals(h1, h2);
    }
}
