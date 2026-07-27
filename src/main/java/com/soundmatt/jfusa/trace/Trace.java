package com.soundmatt.jfusa.trace;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.lint.LintRules;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Requirements traceability engine and coverage mapping.
 * Scans for {@code //fusa:req} and {@code //fusa:test} annotations.
 * Supports HLR/LLR hierarchy validation (Feature 1).
 */
public final class Trace {

    private static final Pattern REQ_ANNOT  = Pattern.compile("//fusa:req\\s+(\\S+)");
    private static final Pattern TEST_ANNOT = Pattern.compile("//fusa:test\\s+(\\S+)");
    private static final String REQS_FILE   = ".fusa-reqs.json";

    static {
        Engine.DEFAULT.mustRegister(new RuleTraceability());
        Engine.DEFAULT.mustRegister(new RuleDanglingTestRef());
    }

    private Trace() {}
    public static void activate() {}

    // ── HLR/LLR types ────────────────────────────────────────────────────────

    /** A requirement loaded from .fusa-reqs.json with optional parent_id for HLR/LLR hierarchy. */
    //fusa:req REQ-HLR001
    public record Requirement(String id, String title, String parentId) {
        /** Returns true when this requirement has a parent (i.e. is an LLR). */
        public boolean isLlr() { return parentId != null && !parentId.isBlank(); }
        /** Returns true when this requirement has no parent (i.e. is an HLR). */
        public boolean isHlr() { return parentId == null || parentId.isBlank(); }
    }

    /**
     * Result of HLR/LLR hierarchy validation.
     *
     * @param orphanLlrs     LLR ids whose parent_id does not match any known HLR
     * @param childlessHlrs  HLR ids that have no LLR children
     * @param hasViolations  true when either list is non-empty
     */
    //fusa:req REQ-HLR002
    public record HlrLlrResult(
            List<String> orphanLlrs,
            List<String> childlessHlrs,
            boolean hasViolations) {}

    // ── Annotation scanning ───────────────────────────────────────────────────

    //fusa:req REQ-TRACE004
    public record Annotation(String reqId, String file, int line, String type) {}

    /**
     * §1.4.1 false-positive filtering: a {@code //fusa:req}/{@code //fusa:test} tag is only a
     * genuine annotation when the text is a real Java line comment — not merely text that
     * happens to appear inside a string literal or a text block (both common in this repo's own
     * test fixtures, which construct example source as literal strings to feed into scanners
     * under test). Since {@code //} has no meaning inside a string/text block, any match whose
     * start position sits inside one is a false positive and must be discarded, not counted.
     *
     * <p>Returns a boolean mask, one entry per character of {@code line}: {@code true} means
     * "inside a string literal or text block" (filter out any match starting there). {@code
     * textBlockState[0]} is mutable, single-element, persistent state carried by the caller
     * across successive lines of the same file to track multi-line {@code """} text blocks.
     */
    static boolean[] lineInsideStringMask(String line, boolean[] textBlockState) {
        int n = line.length();
        boolean[] mask = new boolean[n];
        boolean inRegular = false;
        int i = 0;
        while (i < n) {
            if (textBlockState[0]) {
                if (i + 2 < n && line.charAt(i) == '"' && line.charAt(i + 1) == '"' && line.charAt(i + 2) == '"') {
                    mask[i] = mask[i + 1] = mask[i + 2] = true;
                    textBlockState[0] = false;
                    i += 3;
                } else {
                    mask[i] = true;
                    i++;
                }
                continue;
            }
            if (inRegular) {
                char c = line.charAt(i);
                if (c == '\\' && i + 1 < n) {
                    mask[i] = true;
                    mask[i + 1] = true;
                    i += 2;
                    continue;
                }
                mask[i] = true;
                if (c == '"') inRegular = false;
                i++;
                continue;
            }
            if (i + 2 < n && line.charAt(i) == '"' && line.charAt(i + 1) == '"' && line.charAt(i + 2) == '"') {
                mask[i] = mask[i + 1] = mask[i + 2] = true;
                textBlockState[0] = true;
                i += 3;
                continue;
            }
            if (line.charAt(i) == '"') {
                mask[i] = true;
                inRegular = true;
                i++;
                continue;
            }
            i++; // normal code character; mask[i] stays false
        }
        return mask;
    }

    /**
     * Finds the start index of the first genuine {@code //} line comment on {@code line} (i.e.
     * the first {@code //} not sitting inside a string/text block per {@code mask}), or -1 if
     * the line has no real comment. A tag only counts as a real annotation when it IS that first
     * comment — this rejects "//fusa:req"/"//fusa:test"-shaped text that merely appears as prose
     * further inside an unrelated descriptive comment (e.g. "// see //fusa:req REQ-1 for why").
     */
    private static int firstRealCommentStart(String line, boolean[] mask) {
        for (int i = 0; i < line.length() - 1; i++) {
            if (!mask[i] && line.charAt(i) == '/' && line.charAt(i + 1) == '/') return i;
        }
        return -1;
    }

    public static List<Annotation> scanAnnotations(Path root, Config cfg) throws IOException {
        List<Annotation> out = new ArrayList<>();
        for (Path f : LintRules.javaFiles(root, cfg)) {
            List<String> lines = LintRules.readLines(f);
            String rel = root.relativize(f).toString();
            boolean[] textBlockState = {false};
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                boolean[] mask = lineInsideStringMask(line, textBlockState);
                int firstComment = firstRealCommentStart(line, mask);
                Matcher rm = REQ_ANNOT.matcher(line);
                while (rm.find()) {
                    if (rm.start() == firstComment) out.add(new Annotation(rm.group(1), rel, i + 1, "impl"));
                }
                Matcher tm = TEST_ANNOT.matcher(line);
                while (tm.find()) {
                    if (tm.start() == firstComment) out.add(new Annotation(tm.group(1), rel, i + 1, "test"));
                }
            }
        }
        return out;
    }

    // ── Traceability matrix ───────────────────────────────────────────────────

    /** Aggregates scanned {@code //fusa:req}/{@code //fusa:test} annotations into a per-requirement matrix. */
    //fusa:req REQ-TRACE004
    public static Map<String, List<Annotation>> buildMatrix(Path root, Config cfg) throws IOException {
        Map<String, List<Annotation>> matrix = new LinkedHashMap<>();
        for (Annotation a : scanAnnotations(root, cfg)) {
            matrix.computeIfAbsent(a.reqId(), k -> new ArrayList<>()).add(a);
        }
        return matrix;
    }

    public static String renderText(Map<String, List<Annotation>> matrix) {
        if (matrix.isEmpty()) return "No //fusa:req or //fusa:test annotations found.\n";
        var sb = new StringBuilder();
        sb.append("Requirement Traceability Matrix\n");
        sb.append("=".repeat(60)).append('\n');
        for (var e : matrix.entrySet()) {
            sb.append(e.getKey()).append('\n');
            for (Annotation a : e.getValue()) {
                sb.append("  [").append(a.type()).append("] ")
                        .append(a.file()).append(':').append(a.line()).append('\n');
            }
        }
        sb.append("-".repeat(60)).append('\n');
        sb.append("Total requirements annotated: ").append(matrix.size()).append('\n');
        long tested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a ->
                        a.type().equals("test") || a.type().equals("sec-test"))).count();
        long secTested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a -> a.type().equals("sec-test"))).count();
        sb.append("Requirements with test coverage: ").append(tested).append('\n');
        sb.append("Security-tested requirements: ").append(secTested).append('\n');
        if (matrix.size() > 0) {
            sb.append(String.format("Test coverage: %.0f%%\n", 100.0 * tested / matrix.size()));
        }
        return sb.toString();
    }

    /** §5 canonical JSON shape: §3.1 envelope + requirements[] + tags[] + coverage. */
    public static String renderJson(Map<String, List<Annotation>> matrix) {
        return renderJson(matrix, null);
    }

    /** §5 canonical JSON shape with title/standard fields populated from .fusa-reqs.json. */
    public static String renderJson(Map<String, List<Annotation>> matrix, Path root) {
        Map<String, Map<String, String>> reqMeta = loadReqsMeta(root);
        var w = new Json.Writer();
        w.objectStart();
        // §3.1 common header
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "trace-matrix");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        // §5 requirements[] — one entry per unique annotated requirement id
        w.key("requirements"); w.arrayStart();
        for (String reqId : matrix.keySet()) {
            w.objectStart();
            w.field("id", reqId);
            Map<String, String> meta = reqMeta.get(reqId);
            if (meta != null) {
                String title = meta.get("title");
                String standard = meta.get("standard");
                if (title != null && !title.isEmpty()) w.field("title", title);
                if (standard != null && !standard.isEmpty()) w.field("standard", standard);
            }
            w.objectEnd();
        }
        w.arrayEnd();
        // §5 tags[] — flat array; kind MUST be "impl"|"test"|"sec-test"
        w.key("tags"); w.arrayStart();
        for (var e : matrix.entrySet()) {
            for (Annotation a : e.getValue()) {
                w.objectStart();
                w.field("requirementId", a.reqId());
                w.field("file", a.file());
                w.field("line", a.line());
                w.field("kind", a.type());
                w.objectEnd();
            }
        }
        w.arrayEnd();
        // §5 coverage
        int total = matrix.size();
        long traced = matrix.entrySet().stream().filter(e -> !e.getValue().isEmpty()).count();
        long tested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a ->
                        a.type().equals("test") || a.type().equals("sec-test"))).count();
        long secTested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a -> a.type().equals("sec-test"))).count();
        w.key("coverage"); w.objectStart();
        w.field("totalRequirements", total);
        w.field("tracedRequirements", traced);
        w.field("testedRequirements", tested);
        w.field("secTestedRequirements", secTested);
        w.objectEnd();
        w.objectEnd();
        return w.toPretty();
    }

    // ── Requirements metadata lookup ──────────────────────────────────────────

    /** Reads .fusa-reqs.json and returns a map of reqId → {title, standard}. */
    private static Map<String, Map<String, String>> loadReqsMeta(Path root) {
        if (root == null) return Map.of();
        Path reqs = root.resolve(REQS_FILE);
        if (!Files.exists(reqs)) return Map.of();
        try {
            String json = Files.readString(reqs);
            Map<String, Map<String, String>> out = new LinkedHashMap<>();
            // Extract "requirements":[...] array and parse each {id, title, standard}
            int arrStart = json.indexOf("\"requirements\"");
            if (arrStart < 0) return out;
            int bracket = json.indexOf('[', arrStart);
            if (bracket < 0) return out;
            int depth = 0; int i = bracket;
            StringBuilder arr = new StringBuilder();
            while (i < json.length()) {
                char c = json.charAt(i);
                if (c == '[' || c == '{') depth++;
                if (c == ']' || c == '}') depth--;
                arr.append(c);
                if (depth == 0) break;
                i++;
            }
            // Simple per-object parser: extract id, title, standard from each {...}
            String arrStr = arr.toString();
            int pos = 0;
            while (pos < arrStr.length()) {
                int ob = arrStr.indexOf('{', pos);
                if (ob < 0) break;
                int cb = arrStr.indexOf('}', ob);
                if (cb < 0) break;
                String obj = arrStr.substring(ob, cb + 1);
                String id       = extractField(obj, "id");
                String title    = extractField(obj, "title");
                String standard = extractField(obj, "standard");
                if (id != null && !id.isEmpty()) {
                    Map<String, String> meta = new LinkedHashMap<>();
                    if (title != null)    meta.put("title",    title);
                    if (standard != null) meta.put("standard", standard);
                    out.put(id, meta);
                }
                pos = cb + 1;
            }
            return out;
        } catch (IOException e) {
            return Map.of();
        }
    }

    private static String extractField(String obj, String key) {
        String needle = "\"" + key + "\"";
        int ki = obj.indexOf(needle);
        if (ki < 0) return null;
        int colon = obj.indexOf(':', ki + needle.length());
        if (colon < 0) return null;
        int vs = colon + 1;
        while (vs < obj.length() && (obj.charAt(vs) == ' ' || obj.charAt(vs) == '\t')) vs++;
        if (vs >= obj.length() || obj.charAt(vs) != '"') return null;
        int start = vs + 1;
        int end = obj.indexOf('"', start);
        if (end < 0) return null;
        return obj.substring(start, end);
    }

    // ── HLR/LLR hierarchy ─────────────────────────────────────────────────────

    /**
     * Loads all requirements from .fusa-reqs.json, including parent_id.
     * Requirements without parent_id are HLRs; those with it are LLRs.
     */
    //fusa:req REQ-HLR001
    public static List<Requirement> loadFullRequirements(Path root) {
        if (root == null) return List.of();
        Path reqs = root.resolve(REQS_FILE);
        if (!Files.exists(reqs)) return List.of();
        try {
            String json = Files.readString(reqs);
            Map<String, Object> parsed = Json.parseObject(json);
            List<Object> reqArr = Json.arr(parsed, "requirements");
            List<Requirement> out = new ArrayList<>();
            for (Object obj : reqArr) {
                if (!(obj instanceof Map<?,?> m)) continue;
                @SuppressWarnings("unchecked")
                Map<String, Object> reqMap = (Map<String, Object>) m;
                String id       = Json.str(reqMap, "id", "");
                String title    = Json.str(reqMap, "title", "");
                String parentId = Json.str(reqMap, "parent_id", "");
                if (!id.isBlank()) out.add(new Requirement(id, title, parentId.isBlank() ? null : parentId));
            }
            return out;
        } catch (IOException | Json.JsonParseException e) {
            return List.of();
        }
    }

    /**
     * Validates the HLR/LLR hierarchy:
     * <ul>
     *   <li>Every LLR must have a parent_id pointing to a known HLR.</li>
     *   <li>Every HLR must have at least one LLR child.</li>
     * </ul>
     */
    //fusa:req REQ-HLR002
    public static HlrLlrResult validateHierarchy(List<Requirement> reqs) {
        Set<String> hlrIds = new LinkedHashSet<>();
        for (Requirement r : reqs) {
            if (r.isHlr()) hlrIds.add(r.id());
        }
        List<String> orphanLlrs = new ArrayList<>();
        Set<String> hlrsWithChildren = new LinkedHashSet<>();
        for (Requirement r : reqs) {
            if (r.isLlr()) {
                if (!hlrIds.contains(r.parentId())) {
                    orphanLlrs.add(r.id());
                } else {
                    hlrsWithChildren.add(r.parentId());
                }
            }
        }
        List<String> childlessHlrs = new ArrayList<>();
        for (String hlrId : hlrIds) {
            if (!hlrsWithChildren.contains(hlrId)) childlessHlrs.add(hlrId);
        }
        boolean hasViolations = !orphanLlrs.isEmpty() || !childlessHlrs.isEmpty();
        return new HlrLlrResult(
                Collections.unmodifiableList(orphanLlrs),
                Collections.unmodifiableList(childlessHlrs),
                hasViolations);
    }

    /** Text rendering with optional HLR/LLR hierarchy info appended. */
    public static String renderText(Map<String, List<Annotation>> matrix, HlrLlrResult hlr) {
        String base = renderText(matrix);
        if (hlr == null) return base;
        var sb = new StringBuilder(base);
        sb.append("\nHLR/LLR Hierarchy\n").append("-".repeat(40)).append('\n');
        if (hlr.childlessHlrs().isEmpty() && hlr.orphanLlrs().isEmpty()) {
            sb.append("  No HLR/LLR hierarchy issues found.\n");
        } else {
            for (String id : hlr.childlessHlrs())
                sb.append("  WARN  HLR ").append(id).append(" has no LLR children\n");
            for (String id : hlr.orphanLlrs())
                sb.append("  WARN  LLR ").append(id).append(" references unknown parent\n");
        }
        return sb.toString();
    }

    /** JSON rendering with optional HLR/LLR hierarchy object appended. */
    public static String renderJson(Map<String, List<Annotation>> matrix, Path root, HlrLlrResult hlr) {
        if (hlr == null) return renderJson(matrix, root);
        // Re-build the base JSON but intercept before final objectEnd to add hierarchy
        Map<String, Map<String, String>> reqMeta = loadReqsMeta(root);
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "trace-matrix");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.key("requirements"); w.arrayStart();
        for (String reqId : matrix.keySet()) {
            w.objectStart();
            w.field("id", reqId);
            Map<String, String> meta = reqMeta.get(reqId);
            if (meta != null) {
                String title    = meta.get("title");
                String standard = meta.get("standard");
                if (title    != null && !title.isEmpty())    w.field("title", title);
                if (standard != null && !standard.isEmpty()) w.field("standard", standard);
            }
            w.objectEnd();
        }
        w.arrayEnd();
        w.key("tags"); w.arrayStart();
        for (var e : matrix.entrySet()) {
            for (Annotation a : e.getValue()) {
                w.objectStart();
                w.field("requirementId", a.reqId());
                w.field("file", a.file());
                w.field("line", a.line());
                w.field("kind", a.type());
                w.objectEnd();
            }
        }
        w.arrayEnd();
        int total = matrix.size();
        long traced = matrix.entrySet().stream().filter(e -> !e.getValue().isEmpty()).count();
        long tested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a ->
                        a.type().equals("test") || a.type().equals("sec-test"))).count();
        long secTested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a -> a.type().equals("sec-test"))).count();
        w.key("coverage"); w.objectStart();
        w.field("totalRequirements", total);
        w.field("tracedRequirements", traced);
        w.field("testedRequirements", tested);
        w.field("secTestedRequirements", secTested);
        w.objectEnd();
        // HLR/LLR hierarchy section
        w.key("hierarchy"); w.objectStart();
        w.field("hasViolations", hlr.hasViolations());
        w.key("childlessHlrs"); w.arrayStart();
        for (String id : hlr.childlessHlrs()) w.value(id);
        w.arrayEnd();
        w.key("orphanLlrs"); w.arrayStart();
        for (String id : hlr.orphanLlrs()) w.value(id);
        w.arrayEnd();
        w.objectEnd();
        w.objectEnd();
        return w.toPretty();
    }

    // ── Gaps report ───────────────────────────────────────────────────────────

    public static List<String> findGaps(Path root, Config cfg) throws IOException {
        Map<String, List<Annotation>> matrix = buildMatrix(root, cfg);
        List<String> gaps = new ArrayList<>();
        for (var e : matrix.entrySet()) {
            boolean hasSrc  = e.getValue().stream().anyMatch(a -> a.type().equals("impl"));
            boolean hasTest = e.getValue().stream().anyMatch(a ->
                    a.type().equals("test") || a.type().equals("sec-test"));
            if (hasSrc && !hasTest) gaps.add(e.getKey());
        }
        return gaps;
    }

    // ── TRACE001 rule ─────────────────────────────────────────────────────────

    static final class RuleTraceability implements Rule {
        public String id() { return "TRACE001"; }
        public String description() { return "All annotated requirements should have at least one //fusa:test reference."; }

        //fusa:req REQ-TRACE001
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<String> gaps = findGaps(root, cfg);
            List<Finding> out = new ArrayList<>();
            for (String reqId : gaps) {
                out.add(Finding.builder("TRACE001", Severity.WARNING,
                        "requirement " + reqId + " has source annotations but no //fusa:test coverage",
                        new FuSa.Location(".fusa-reqs.json"))
                        .category(FuSa.Category.requirement)
                        .remediation("add //fusa:test " + reqId + " in a JUnit test covering this requirement")
                        .build());
            }
            return out;
        }
    }

    // ── §1.4.1 / §5 --func-coverage ─────────────────────────────────────────────

    /** A public method/constructor-less declaration considered exempt from the func-coverage gate. */
    private static final Set<String> EXEMPT_METHOD_NAMES = Set.of("id", "description", "activate");

    /**
     * Heuristic detector for a concrete {@code public} method declaration header. Requires a
     * return type token before the method name, which structurally excludes constructors
     * (a constructor has only its class name before the parameter list, with no separate return
     * type token) as well as class/interface/enum/record declarations (no parameter list).
     */
    private static final Pattern PUBLIC_METHOD = Pattern.compile(
            "^\\s*public\\s+(?:static\\s+|final\\s+|synchronized\\s+|abstract\\s+|default\\s+)*" +
            "(?:<[^>]*>\\s*)?" +
            "[\\w][\\w.\\[\\]<>,\\s]*?\\s+(\\w+)\\s*\\([^)]*\\)\\s*(?:throws\\s+[\\w.,\\s]+)?\\s*\\{");

    /** True when {@code name} is a getter/setter (JavaBean convention) or a known no-op interface shim. */
    private static boolean isExemptMethodName(String name) {
        if (EXEMPT_METHOD_NAMES.contains(name)) return true;
        if (name.length() > 3 && name.startsWith("get") && Character.isUpperCase(name.charAt(3))) return true;
        if (name.length() > 2 && name.startsWith("is")  && Character.isUpperCase(name.charAt(2))) return true;
        if (name.length() > 3 && name.startsWith("set") && Character.isUpperCase(name.charAt(3))) return true;
        return false;
    }

    /**
     * @param totalFunctions  number of non-exempt public methods found
     * @param taggedFunctions how many of those carry a {@code //fusa:req} tag directly above (or
     *                        within a few lines above, allowing for javadoc/annotations in between)
     * @param percentage      100.0 when totalFunctions is 0 (nothing to cover, gate trivially passes)
     */
    public record FuncCoverageResult(int totalFunctions, int taggedFunctions, double percentage) {}

    /**
     * Computes the §1.4.1/§5 function-coverage figure: the percentage of public methods (excluding
     * getters/setters, constructors, and no-op {@code id()}/{@code description()}/{@code activate()}
     * shims) carrying a {@code //fusa:req} tag directly above them. Reuses {@link #scanAnnotations}
     * so the same string-literal/text-block false-positive filtering applies here too.
     */
    //fusa:req REQ-TRACE002
    public static FuncCoverageResult computeFuncCoverage(Path root, Config cfg) throws IOException {
        Map<String, Set<Integer>> implLinesByFile = new HashMap<>();
        for (Annotation a : scanAnnotations(root, cfg)) {
            if (a.type().equals("impl")) {
                implLinesByFile.computeIfAbsent(a.file(), k -> new TreeSet<>()).add(a.line());
            }
        }

        int total = 0, tagged = 0;
        for (Path f : LintRules.javaFiles(root, cfg)) {
            List<String> lines = LintRules.readLines(f);
            String rel = root.relativize(f).toString();
            Set<Integer> implLines = implLinesByFile.getOrDefault(rel, Set.of());
            boolean[] textBlockState = {false};
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                boolean[] mask = lineInsideStringMask(line, textBlockState);
                Matcher m = PUBLIC_METHOD.matcher(line);
                if (!m.find() || mask[m.start()]) continue;
                String name = m.group(1);
                if (isExemptMethodName(name)) continue;
                total++;
                if (hasReqTagDirectlyAbove(lines, i, implLines)) tagged++;
            }
        }
        double pct = total == 0 ? 100.0 : (100.0 * tagged / total);
        return new FuncCoverageResult(total, tagged, pct);
    }

    /**
     * §1.4.1 item 1 ("directly above, or in the doc comment of"): walks upward from the method
     * declaration at {@code lines.get(methodLineIdx)}, skipping over blank lines, annotations
     * (e.g. {@code @Override}), and javadoc/comment lines, and returns true only if an
     * impl-annotation line is reached before any other real code line — so a tag correctly
     * covers only the single method it is written directly above, never a sibling method too.
     */
    private static boolean hasReqTagDirectlyAbove(List<String> lines, int methodLineIdx, Set<Integer> implLines) {
        for (int idx = methodLineIdx - 1; idx >= 0; idx--) {
            if (implLines.contains(idx + 1)) return true;
            String prev = lines.get(idx).strip();
            if (prev.isEmpty()) continue;
            if (prev.startsWith("@")) continue;
            if (prev.startsWith("*") || prev.startsWith("/**") || prev.startsWith("//") || prev.endsWith("*/")) continue;
            break; // hit real code — the tag (if any) belongs to a different declaration
        }
        return false;
    }

    // ── §1.4.1 dangling test-reference detection (TRACE002) ────────────────────

    static final class RuleDanglingTestRef implements Rule {
        public String id() { return "TRACE002"; }
        public String description() { return "Every //fusa:test tag must reference a requirement id registered in .fusa-reqs.json."; }

        //fusa:req REQ-TRACE003
        public List<Finding> run(Path root, Config cfg) throws IOException {
            List<Finding> out = new ArrayList<>();
            if (root == null || !Files.exists(root.resolve(REQS_FILE))) return out; // nothing to validate against
            Set<String> knownIds = loadReqsMeta(root).keySet();
            for (Annotation a : scanAnnotations(root, cfg)) {
                if (!a.type().equals("test") && !a.type().equals("sec-test")) continue;
                if (knownIds.contains(a.reqId())) continue;
                out.add(Finding.builder("TRACE002", Severity.WARNING,
                        "//fusa:test " + a.reqId() + " references an unknown requirement id (not present in .fusa-reqs.json)",
                        new FuSa.Location(a.file(), a.line()))
                        .category(FuSa.Category.requirement)
                        .remediation("register " + a.reqId() + " in .fusa-reqs.json via 'jfusa req add', or fix the typo")
                        .build());
            }
            return out;
        }
    }
}
