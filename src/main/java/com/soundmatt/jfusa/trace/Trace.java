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

    /**
     * §5 coverage counters. Per requirement: {@code tracedRequirements} counts it if it has ≥1 tag
     * of any kind; {@code testedRequirements} counts it if it has a {@code test} or {@code sec-test}
     * tag; {@code secTestedRequirements} counts it only if it has a {@code sec-test} tag.
     */
    public record CoverageCounts(int total, long traced, long tested, long secTested) {
        /** Percentage 0–100 of {@link #tested()} out of {@link #total()}; 100.0 when total is 0. */
        public double testedPct() { return total == 0 ? 100.0 : 100.0 * tested / total; }
        /** Percentage 0–100 of {@link #secTested()} out of {@link #total()}; 100.0 when total is 0. */
        public double secTestedPct() { return total == 0 ? 100.0 : 100.0 * secTested / total; }
    }

    /** Computes the §5 coverage counters over the full matrix (used by both renderers and the CLI gates). */
    //fusa:req REQ-TRACE005
    public static CoverageCounts computeCoverage(Map<String, List<Annotation>> matrix) {
        int total = matrix.size();
        long traced = matrix.entrySet().stream().filter(e -> !e.getValue().isEmpty()).count();
        long tested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a ->
                        a.type().equals("test") || a.type().equals("sec-test"))).count();
        long secTested = matrix.entrySet().stream()
                .filter(e -> e.getValue().stream().anyMatch(a -> a.type().equals("sec-test"))).count();
        return new CoverageCounts(total, traced, tested, secTested);
    }

    /**
     * §5 {@code --gaps}: returns the subset of {@code matrix} whose requirements carry no tag of
     * kind {@code test} or {@code sec-test} (regardless of whether they carry an {@code impl} tag —
     * a broader set than {@link #findGaps}, which additionally requires an {@code impl} tag for the
     * TRACE001 lint rule's narrower "annotated but untested" purpose).
     */
    public static Map<String, List<Annotation>> untestedMatrix(Map<String, List<Annotation>> matrix) {
        Map<String, List<Annotation>> out = new LinkedHashMap<>();
        for (var e : matrix.entrySet()) {
            boolean hasTest = e.getValue().stream().anyMatch(a ->
                    a.type().equals("test") || a.type().equals("sec-test"));
            if (!hasTest) out.put(e.getKey(), e.getValue());
        }
        return out;
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
    //fusa:req REQ-TRACE-JSON001
    private static Map<String, Map<String, String>> loadReqsMeta(Path root) {
        if (root == null) return Map.of();
        Path reqs = root.resolve(REQS_FILE);
        if (!Files.exists(reqs)) return Map.of();
        try {
            Map<String, Object> doc = Json.parseObject(Files.readString(reqs));
            List<Object> requirements = Json.arr(doc, "requirements");
            Map<String, Map<String, String>> out = new LinkedHashMap<>();
            for (Object r : requirements) {
                @SuppressWarnings("unchecked")
                Map<String, Object> req = (Map<String, Object>) r;
                String id = Json.str(req, "id", "");
                if (id.isEmpty()) continue;
                Map<String, String> meta = new LinkedHashMap<>();
                String title    = Json.str(req, "title", null);
                String standard = Json.str(req, "standard", null);
                if (title != null)    meta.put("title",    title);
                if (standard != null) meta.put("standard", standard);
                out.put(id, meta);
            }
            return out;
        } catch (IOException | Json.JsonParseException | ClassCastException e) {
            return Map.of();
        }
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
        return renderText(matrix, hlr, false);
    }

    /**
     * Text rendering with optional HLR/LLR hierarchy info appended and optional §5 {@code --gaps}
     * filtering: when {@code gapsOnly} is true, only requirements with no test-or-sec-test tag are
     * listed in the body, but the coverage footer still reports the full totals.
     */
    public static String renderText(Map<String, List<Annotation>> matrix, HlrLlrResult hlr, boolean gapsOnly) {
        if (hlr == null && !gapsOnly) return renderText(matrix);
        Map<String, List<Annotation>> displayMatrix = gapsOnly ? untestedMatrix(matrix) : matrix;
        var sb = new StringBuilder();
        if (matrix.isEmpty()) {
            sb.append("No //fusa:req or //fusa:test annotations found.\n");
        } else if (gapsOnly && displayMatrix.isEmpty()) {
            sb.append("No untested requirements — full test coverage.\n");
        } else {
            sb.append("Requirement Traceability Matrix\n");
            sb.append("=".repeat(60)).append('\n');
            for (var e : displayMatrix.entrySet()) {
                sb.append(e.getKey()).append('\n');
                for (Annotation a : e.getValue()) {
                    sb.append("  [").append(a.type()).append("] ")
                            .append(a.file()).append(':').append(a.line()).append('\n');
                }
            }
            sb.append("-".repeat(60)).append('\n');
        }
        if (!matrix.isEmpty()) {
            CoverageCounts cov = computeCoverage(matrix);
            sb.append("Total requirements annotated: ").append(cov.total()).append('\n');
            sb.append("Requirements with test coverage: ").append(cov.tested()).append('\n');
            sb.append("Security-tested requirements: ").append(cov.secTested()).append('\n');
            sb.append(String.format("Test coverage: %.0f%%\n", cov.testedPct()));
        }
        if (hlr != null) {
            sb.append("\nHLR/LLR Hierarchy\n").append("-".repeat(40)).append('\n');
            if (hlr.childlessHlrs().isEmpty() && hlr.orphanLlrs().isEmpty()) {
                sb.append("  No HLR/LLR hierarchy issues found.\n");
            } else {
                for (String id : hlr.childlessHlrs())
                    sb.append("  WARN  HLR ").append(id).append(" has no LLR children\n");
                for (String id : hlr.orphanLlrs())
                    sb.append("  WARN  LLR ").append(id).append(" references unknown parent\n");
            }
        }
        return sb.toString();
    }

    /** JSON rendering with optional HLR/LLR hierarchy object appended. */
    public static String renderJson(Map<String, List<Annotation>> matrix, Path root, HlrLlrResult hlr) {
        return renderJson(matrix, root, hlr, false);
    }

    /**
     * JSON rendering with optional HLR/LLR hierarchy object appended and optional §5 {@code --gaps}
     * filtering: when {@code gapsOnly} is true, {@code requirements[]}/{@code tags[]} are restricted
     * to requirements with no test-or-sec-test tag, but {@code coverage} MUST still report the full
     * totals (§5) so the gap set doesn't distort the percentage.
     */
    public static String renderJson(Map<String, List<Annotation>> matrix, Path root, HlrLlrResult hlr, boolean gapsOnly) {
        if (hlr == null && !gapsOnly) return renderJson(matrix, root);
        Map<String, List<Annotation>> displayMatrix = gapsOnly ? untestedMatrix(matrix) : matrix;
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
        for (String reqId : displayMatrix.keySet()) {
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
        for (var e : displayMatrix.entrySet()) {
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
        // §5 coverage MUST report the full totals even under --gaps.
        CoverageCounts cov = computeCoverage(matrix);
        w.key("coverage"); w.objectStart();
        w.field("totalRequirements", cov.total());
        w.field("tracedRequirements", cov.traced());
        w.field("testedRequirements", cov.tested());
        w.field("secTestedRequirements", cov.secTested());
        w.objectEnd();
        if (hlr != null) {
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
        }
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
     * Group 1 is the return type, group 2 the method name, group 3 the raw parameter list.
     */
    private static final Pattern PUBLIC_METHOD = Pattern.compile(
            "^\\s*public\\s+(?:static\\s+|final\\s+|synchronized\\s+|abstract\\s+|default\\s+)*" +
            "(?:<[^>]*>\\s*)?" +
            "([\\w][\\w.\\[\\]<>,\\s]*?)\\s+(\\w+)\\s*\\(([^)]*)\\)\\s*(?:throws\\s+[\\w.,\\s]+)?\\s*\\{");

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
     * A single real, non-exempt public method/constructor-less declaration found while building
     * the project's "real component" inventory (§1.6 rule 4) — the shared unit {@link
     * #computeFuncCoverage} and {@code Fmea.derive} both consume, so the two scanners can never
     * independently drift into counting different populations (the root cause of x-FuSa/java-FuSa#33).
     *
     * @param file       project-relative path (§4 rule)
     * @param line       1-based line number of the declaration
     * @param name       method name
     * @param returnType raw return-type text as written (may include generics/arrays)
     * @param params     raw parameter-list text as written (empty string for a no-arg method)
     */
    public record ComponentMethod(String file, int line, String name, String returnType, String params) {}

    private record FileScan(String file, List<String> lines, List<ComponentMethod> methods) {}

    /**
     * Walks every non-test-tree {@code .java} file and returns each real, non-exempt public
     * method declaration found, per file, along with that file's full line list (so a caller like
     * {@link #computeFuncCoverage} can look upward from the declaration for a req tag without
     * re-reading the file). Test-source files (§1.6 rule 4 — {@link LintRules#isTestSourcePath})
     * are excluded so a fixture class is never mistaken for a real project component.
     */
    private static List<FileScan> scanRealMethodsByFile(Path root, Config cfg) throws IOException {
        List<FileScan> out = new ArrayList<>();
        for (Path f : LintRules.javaFiles(root, cfg)) {
            if (LintRules.isTestSourcePath(root, f)) continue;
            String rel = root.relativize(f).toString();
            List<String> lines = LintRules.readLines(f);
            List<ComponentMethod> methods = new ArrayList<>();
            boolean[] textBlockState = {false};
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                boolean[] mask = lineInsideStringMask(line, textBlockState);
                Matcher m = PUBLIC_METHOD.matcher(line);
                if (!m.find() || mask[m.start()]) continue;
                String name = m.group(2);
                if (isExemptMethodName(name)) continue;
                methods.add(new ComponentMethod(rel, i + 1, name, m.group(1).trim(), m.group(3)));
            }
            out.add(new FileScan(rel, lines, methods));
        }
        return out;
    }

    /**
     * Public "real project component" inventory (§1.6 rule 4) — the same population {@link
     * #computeFuncCoverage} uses as its denominator, exposed so other artifact-producing scanners
     * (e.g. {@code Fmea.derive}) can reuse it directly instead of maintaining a second,
     * independently-drifting method-detection regex (§1.6 rule 4 implementer guidance, spec
     * v1.15.0).
     */
    //fusa:req REQ-TRACE005
    public static List<ComponentMethod> scanComponentMethods(Path root, Config cfg) throws IOException {
        List<ComponentMethod> out = new ArrayList<>();
        for (FileScan fs : scanRealMethodsByFile(root, cfg)) out.addAll(fs.methods());
        return out;
    }

    /**
     * Computes the §1.4.1/§5 function-coverage figure: the percentage of public methods (excluding
     * getters/setters, constructors, no-op {@code id()}/{@code description()}/{@code activate()}
     * shims, and the test-source tree — §1.6 rule 4) carrying a {@code //fusa:req} tag directly
     * above them. Reuses {@link #scanAnnotations} so the same string-literal/text-block
     * false-positive filtering applies here too.
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
        for (FileScan fs : scanRealMethodsByFile(root, cfg)) {
            Set<Integer> implLines = implLinesByFile.getOrDefault(fs.file(), Set.of());
            for (ComponentMethod cm : fs.methods()) {
                total++;
                if (hasReqTagDirectlyAbove(fs.lines(), cm.line() - 1, implLines)) tagged++;
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
