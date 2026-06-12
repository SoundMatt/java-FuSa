package com.soundmatt.jfusa.internal;

import java.io.IOException;
import java.io.Reader;
import java.util.*;

/**
 * Minimal zero-dependency JSON encoder and parser.
 *
 * <p>Encoder: builds JSON strings via {@link Writer}.
 * Parser: reads a JSON value from a {@link Reader} into plain Java objects
 * ({@code Map<String,Object>}, {@code List<Object>}, {@code String},
 * {@code Double}, {@code Boolean}, {@code null}).
 */
public final class Json {

    private Json() {}

    // ── Encoder ───────────────────────────────────────────────────────────────

    public static final class Writer {
        private final StringBuilder sb;
        private boolean needsComma = false;

        public Writer() { this.sb = new StringBuilder(); }

        public Writer objectStart() { comma(); sb.append('{'); needsComma = false; return this; }
        public Writer objectEnd()   { sb.append('}'); needsComma = true; return this; }
        public Writer arrayStart()  { comma(); sb.append('['); needsComma = false; return this; }
        public Writer arrayEnd()    { sb.append(']'); needsComma = true; return this; }

        public Writer key(String k) { comma(); quoted(k); sb.append(':'); needsComma = false; return this; }

        public Writer value(String v) {
            comma();
            if (v == null) sb.append("null");
            else quoted(v);
            needsComma = true;
            return this;
        }

        public Writer value(long v)    { comma(); sb.append(v); needsComma = true; return this; }
        public Writer value(double v)  { comma(); sb.append(v); needsComma = true; return this; }
        public Writer value(boolean v) { comma(); sb.append(v); needsComma = true; return this; }
        public Writer nullValue()      { comma(); sb.append("null"); needsComma = true; return this; }

        public Writer field(String k, String v)  { return key(k).value(v); }
        public Writer field(String k, long v)    { return key(k).value(v); }
        public Writer field(String k, boolean v) { return key(k).value(v); }

        public Writer fieldIfNonBlank(String k, String v) {
            if (v != null && !v.isBlank()) field(k, v);
            return this;
        }

        private void comma() { if (needsComma) sb.append(','); }

        private void quoted(String s) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"'  -> sb.append("\\\"");
                    case '\\' -> sb.append("\\\\");
                    case '\b' -> sb.append("\\b");
                    case '\f' -> sb.append("\\f");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\t' -> sb.append("\\t");
                    default   -> {
                        if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                        else sb.append(c);
                    }
                }
            }
            sb.append('"');
        }

        public String toString() { return sb.toString(); }

        public String toPretty() { return prettify(sb.toString()); }
    }

    /** Minimal pretty-printer (indent = 2 spaces). */
    public static String prettify(String compact) {
        StringBuilder out = new StringBuilder();
        int indent = 0;
        boolean inString = false;
        for (int i = 0; i < compact.length(); i++) {
            char c = compact.charAt(i);
            if (inString) {
                out.append(c);
                if (c == '"' && (i == 0 || compact.charAt(i - 1) != '\\')) inString = false;
                continue;
            }
            switch (c) {
                case '"' -> { out.append(c); inString = true; }
                case '{', '[' -> {
                    out.append(c);
                    if (i + 1 < compact.length() && compact.charAt(i + 1) != '}' && compact.charAt(i + 1) != ']') {
                        out.append('\n');
                        indent++;
                        out.append("  ".repeat(indent));
                    }
                }
                case '}', ']' -> {
                    char peek = i > 0 ? compact.charAt(i - 1) : 0;
                    if (peek != '{' && peek != '[') {
                        out.append('\n');
                        indent = Math.max(0, indent - 1);
                        out.append("  ".repeat(indent));
                    } else {
                        indent = Math.max(0, indent - 1);
                    }
                    out.append(c);
                }
                case ',' -> {
                    out.append(c);
                    out.append('\n');
                    out.append("  ".repeat(indent));
                }
                case ':' -> out.append(": ");
                default  -> out.append(c);
            }
        }
        return out.toString();
    }

    // ── Parser ────────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json) {
        Object v = parse(json);
        if (v instanceof Map<?,?> m) return (Map<String, Object>) m;
        throw new JsonParseException("expected JSON object, got " + (v == null ? "null" : v.getClass().getSimpleName()));
    }

    public static Object parse(String json) {
        if (json == null) throw new JsonParseException("null input");
        return new Parser(json.strip()).parseValue();
    }

    private static final class Parser {
        private final String src;
        private int pos;

        Parser(String src) { this.src = src; }

        Object parseValue() {
            skipWs();
            if (pos >= src.length()) throw new JsonParseException("unexpected end of input");
            char c = src.charAt(pos);
            return switch (c) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't' -> parseLiteral("true", Boolean.TRUE);
                case 'f' -> parseLiteral("false", Boolean.FALSE);
                case 'n' -> parseLiteral("null", null);
                default  -> {
                    if (c == '-' || Character.isDigit(c)) yield parseNumber();
                    throw new JsonParseException("unexpected char '" + c + "' at pos " + pos);
                }
            };
        }

        private Map<String, Object> parseObject() {
            expect('{'); skipWs();
            Map<String, Object> map = new LinkedHashMap<>();
            if (peek() == '}') { pos++; return map; }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs(); expect(':');
                Object val = parseValue();
                map.put(key, val);
                skipWs();
                char nx = peek();
                if (nx == '}') { pos++; break; }
                if (nx == ',') { pos++; } else throw new JsonParseException("expected ',' or '}'");
            }
            return map;
        }

        private List<Object> parseArray() {
            expect('['); skipWs();
            List<Object> list = new ArrayList<>();
            if (peek() == ']') { pos++; return list; }
            while (true) {
                list.add(parseValue());
                skipWs();
                char nx = peek();
                if (nx == ']') { pos++; break; }
                if (nx == ',') pos++; else throw new JsonParseException("expected ',' or ']'");
            }
            return list;
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < src.length()) {
                char c = src.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= src.length()) break;
                    char esc = src.charAt(pos++);
                    sb.append(switch (esc) {
                        case '"', '\\', '/' -> esc;
                        case 'b' -> '\b';
                        case 'f' -> '\f';
                        case 'n' -> '\n';
                        case 'r' -> '\r';
                        case 't' -> '\t';
                        case 'u' -> {
                            String hex = src.substring(pos, Math.min(pos + 4, src.length()));
                            pos += 4;
                            yield (char) Integer.parseInt(hex, 16);
                        }
                        default -> throw new JsonParseException("bad escape: \\" + esc);
                    });
                } else {
                    sb.append(c);
                }
            }
            throw new JsonParseException("unterminated string");
        }

        private Object parseLiteral(String tok, Object val) {
            if (src.startsWith(tok, pos)) { pos += tok.length(); return val; }
            throw new JsonParseException("expected '" + tok + "' at pos " + pos);
        }

        private Object parseNumber() {
            int start = pos;
            if (pos < src.length() && src.charAt(pos) == '-') pos++;
            while (pos < src.length() && (Character.isDigit(src.charAt(pos)) || src.charAt(pos) == '.' ||
                    src.charAt(pos) == 'e' || src.charAt(pos) == 'E' ||
                    src.charAt(pos) == '+' || src.charAt(pos) == '-')) pos++;
            String num = src.substring(start, pos);
            if (num.contains(".") || num.contains("e") || num.contains("E"))
                return Double.parseDouble(num);
            try { return Long.parseLong(num); } catch (NumberFormatException e) { return Double.parseDouble(num); }
        }

        private void skipWs() { while (pos < src.length() && src.charAt(pos) <= ' ') pos++; }
        private char peek() { return pos < src.length() ? src.charAt(pos) : 0; }
        private void expect(char c) {
            if (pos >= src.length() || src.charAt(pos) != c)
                throw new JsonParseException("expected '" + c + "' at pos " + pos);
            pos++;
        }
    }

    public static final class JsonParseException extends RuntimeException {
        public JsonParseException(String msg) { super(msg); }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static String str(Map<String, Object> map, String key, String def) {
        Object v = map.get(key);
        if (v instanceof String s) return s;
        if (v instanceof Map<?,?> m) return def; // wrong type
        return v != null ? v.toString() : def;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof Map<?,?> m) return (Map<String, Object>) m;
        return new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    public static List<Object> arr(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof List<?> l) return (List<Object>) l;
        return new ArrayList<>();
    }
}
