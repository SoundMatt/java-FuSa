package com.soundmatt.jfusa.internal;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.*;

/**
 * A practical subset of RFC 8785 (the JSON Canonicalization Scheme) over the
 * plain Java object model {@link Json#parse} produces ({@code Map<String,Object>},
 * {@code List<Object>}, {@code String}, {@code Long}/{@code Double}, {@code Boolean},
 * {@code null}): object keys sorted lexicographically at every level, no
 * insignificant whitespace, numbers in shortest round-trip form.
 *
 * <p>Used to compute the reproducible content hashes the x-FuSa spec requires
 * (§6 {@code qualify.hash}, §1.6.2 attestation {@code contentHash}) — a hash
 * MUST be independent of key/array ordering, not merely of pretty-printing.
 */
public final class CanonJson {

    private CanonJson() {}

    /** Canonicalizes a parsed JSON value (as produced by {@link Json#parse}) to a string. */
    //fusa:req REQ-CANON001
    public static String canonicalize(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value);
        return sb.toString();
    }

    /** Parses {@code json} and canonicalizes the result in one step. */
    //fusa:req REQ-CANON001
    public static String canonicalizeJson(String json) {
        return canonicalize(Json.parse(json));
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String s) { writeString(sb, s); return; }
        if (v instanceof Boolean b) { sb.append(b.booleanValue() ? "true" : "false"); return; }
        if (v instanceof Long || v instanceof Integer) { sb.append(v.toString()); return; }
        if (v instanceof Double d) { sb.append(canonicalNumber(d)); return; }
        if (v instanceof Map<?, ?> m) {
            Map<String, Object> map = (Map<String, Object>) m;
            List<String> keys = new ArrayList<>(map.keySet());
            Collections.sort(keys);
            sb.append('{');
            boolean first = true;
            for (String k : keys) {
                if (!first) sb.append(',');
                first = false;
                writeString(sb, k);
                sb.append(':');
                write(sb, map.get(k));
            }
            sb.append('}');
            return;
        }
        if (v instanceof List<?> l) {
            sb.append('[');
            boolean first = true;
            for (Object e : l) {
                if (!first) sb.append(',');
                first = false;
                write(sb, e);
            }
            sb.append(']');
            return;
        }
        throw new IllegalArgumentException("canonjson: unsupported type " + v.getClass());
    }

    /** Shortest round-trip form: an integral double serialises with no trailing ".0". */
    private static String canonicalNumber(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            throw new IllegalArgumentException("canonjson: non-finite number");
        }
        if (d == Math.floor(d) && Math.abs(d) < 1e15) {
            return Long.toString((long) d);
        }
        return Double.toString(d);
    }

    private static void writeString(StringBuilder sb, String s) {
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
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }

    /** {@code sha256:<hex>} over the canonical bytes of {@code value} — §1.6.2/§6 hash convention. */
    //fusa:req REQ-CANON002
    public static String sha256Prefixed(Object value) {
        return "sha256:" + sha256Hex(canonicalize(value));
    }

    //fusa:req REQ-CANON002
    public static String sha256Hex(String canonical) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(canonical.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
