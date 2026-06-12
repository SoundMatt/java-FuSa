package com.soundmatt.jfusa;

import com.soundmatt.jfusa.internal.Json;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class JsonTest {

    @Test
    void writer_producesValidJson_emptyObject() {
        var w = new Json.Writer();
        w.objectStart(); w.objectEnd();
        assertEquals("{}", w.toString());
    }

    @Test
    void writer_producesStringField() {
        var w = new Json.Writer();
        w.objectStart();
        w.field("key", "value");
        w.objectEnd();
        assertTrue(w.toString().contains("\"key\":\"value\""));
    }

    @Test
    void writer_producesLongField() {
        var w = new Json.Writer();
        w.objectStart();
        w.field("n", 42L);
        w.objectEnd();
        assertTrue(w.toString().contains("\"n\":42"));
    }

    @Test
    void writer_producesBooleanField() {
        var w = new Json.Writer();
        w.objectStart();
        w.field("flag", true);
        w.objectEnd();
        assertTrue(w.toString().contains("\"flag\":true"));
    }

    @Test
    void writer_producesArray() {
        var w = new Json.Writer();
        w.arrayStart();
        w.value("a"); w.value("b");
        w.arrayEnd();
        assertEquals("[\"a\",\"b\"]", w.toString());
    }

    @Test
    void writer_escapeSpecialChars() {
        var w = new Json.Writer();
        w.objectStart();
        w.field("msg", "line1\nline2\ttab\"quote");
        w.objectEnd();
        String s = w.toString();
        assertTrue(s.contains("\\n"));
        assertTrue(s.contains("\\t"));
        assertTrue(s.contains("\\\""));
    }

    @Test
    void writer_nestedObjects() {
        var w = new Json.Writer();
        w.objectStart();
        w.key("inner"); w.objectStart();
        w.field("x", 1L);
        w.objectEnd();
        w.objectEnd();
        String s = w.toString();
        assertTrue(s.contains("\"inner\":{\"x\":1}"));
    }

    @Test
    void parser_parsesSimpleObject() {
        Map<String, Object> m = Json.parseObject("{\"a\":\"hello\",\"b\":42}");
        assertEquals("hello", m.get("a"));
        assertEquals(42L, ((Number) m.get("b")).longValue());
    }

    @Test
    void parser_parsesNestedObject() {
        Map<String, Object> m = Json.parseObject("{\"outer\":{\"inner\":\"val\"}}");
        @SuppressWarnings("unchecked")
        Map<String, Object> inner = (Map<String, Object>) m.get("outer");
        assertNotNull(inner);
        assertEquals("val", inner.get("inner"));
    }

    @Test
    void parser_parsesArray() {
        Map<String, Object> m = Json.parseObject("{\"arr\":[1,2,3]}");
        @SuppressWarnings("unchecked")
        List<Object> arr = (List<Object>) m.get("arr");
        assertNotNull(arr);
        assertEquals(3, arr.size());
    }

    @Test
    void parser_parsesNullValue() {
        Map<String, Object> m = Json.parseObject("{\"x\":null}");
        assertNull(m.get("x"));
    }

    @Test
    void parser_parsesBooleans() {
        Map<String, Object> m = Json.parseObject("{\"t\":true,\"f\":false}");
        assertEquals(Boolean.TRUE, m.get("t"));
        assertEquals(Boolean.FALSE, m.get("f"));
    }

    @Test
    void writer_toPretty_hasNewlines() {
        var w = new Json.Writer();
        w.objectStart(); w.field("k", "v"); w.objectEnd();
        assertTrue(w.toPretty().contains("\n"));
    }

    @Test
    void helper_str_returnsDefault_whenMissing() {
        Map<String, Object> m = Map.of("key", "val");
        assertEquals("val", Json.str(m, "key", "def"));
        assertEquals("def", Json.str(m, "missing", "def"));
    }

    @Test
    void roundtrip_complexDocument() {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-test");
        w.key("items"); w.arrayStart();
        w.objectStart(); w.field("id", "A1"); w.field("count", 3L); w.objectEnd();
        w.objectStart(); w.field("id", "A2"); w.field("count", 7L); w.objectEnd();
        w.arrayEnd();
        w.objectEnd();
        String json = w.toString();
        Map<String, Object> parsed = Json.parseObject(json);
        assertEquals("x-fusa-test", parsed.get("schema"));
        @SuppressWarnings("unchecked")
        List<Object> items = (List<Object>) parsed.get("items");
        assertEquals(2, items.size());
    }
}
