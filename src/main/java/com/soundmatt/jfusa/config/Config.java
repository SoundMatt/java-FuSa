package com.soundmatt.jfusa.config;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Project configuration: load, parse, save, and validate {@code .fusa.json}.
 *
 * <p>Conforms to x-FuSa spec v1.10 §1.2.1 schema.
 */
public final class Config {

    public static final String CONFIG_FILE = ".fusa.json";
    public static final String CONFIG_VERSION = "1.0";

    // ── Standard identifiers ─────────────────────────────────────────────────

    //fusa:req REQ-NF003
    public enum Standard {
        ISO26262("iso26262"), IEC61508("iec61508"), ISO21434("iso21434"),
        DO178C("do178c"), IEC62443("iec62443-4-1"), generic("generic");

        private final String canonicalId;
        Standard(String id) { this.canonicalId = id; }

        /** Lowercase canonical id for JSON output per §2.4.1. */
        public String canonicalId() { return canonicalId; }

        public static Standard of(String s) {
            if (s == null || s.isBlank()) return generic;
            // Accept canonical lowercase id (iso26262) or enum name (ISO26262)
            for (Standard st : values()) {
                if (st.canonicalId.equalsIgnoreCase(s) || st.name().equalsIgnoreCase(s)) return st;
            }
            return generic;
        }
    }

    // ── Value types ───────────────────────────────────────────────────────────

    public record ProjectConfig(
            String name,
            String version,
            Standard standard,
            String asil,
            String sil,
            String dal) {

        public ProjectConfig(String name) {
            this(name, "0.1.0", Standard.generic, "", "", "");
        }

        public ProjectConfig(String name, String artifact, Standard standard, String asil, String sil) {
            this(name, "0.1.0", standard, asil, sil, "");
        }
    }

    public record RulesConfig(List<String> exclude, Map<String, String> severity) {
        public RulesConfig() { this(List.of(), Map.of()); }
    }

    public record ReportConfig(String format, String output) {
        public ReportConfig() { this("text", ""); }
    }

    // ── Config ────────────────────────────────────────────────────────────────

    private final String configVersion;
    private final ProjectConfig project;
    private final RulesConfig rules;
    private final ReportConfig report;

    public Config(String configVersion, ProjectConfig project, RulesConfig rules, ReportConfig report) {
        this.configVersion = configVersion;
        this.project = project;
        this.rules = rules;
        this.report = report;
    }

    /** Config-format version (own series, "1.0" per §2.8). */
    public String configVersion() { return configVersion; }

    /** Legacy accessor — returns the configVersion field for backwards compatibility. */
    public String version() { return configVersion; }

    public ProjectConfig project() { return project; }
    public RulesConfig rules() { return rules; }
    public ReportConfig report() { return report; }

    // ── Factory methods ───────────────────────────────────────────────────────

    //fusa:req REQ-CFG005
    public static Config defaultConfig(String name) {
        return new Config(
                CONFIG_VERSION,
                new ProjectConfig(name, "0.1.0", Standard.generic, "", "", ""),
                new RulesConfig(List.of(), Map.of()),
                new ReportConfig("text", ""));
    }

    //fusa:req REQ-CFG001
    public static Config load(Path projectRoot) {
        Path configPath = projectRoot.resolve(CONFIG_FILE);
        if (!Files.exists(configPath)) {
            throw new FuSa.NoConfigException(configPath.toString());
        }
        String content;
        try {
            content = Files.readString(configPath);
        } catch (IOException e) {
            throw new FuSa.NoConfigException(configPath.toString(), e);
        }
        try {
            return parse(content);
        } catch (Json.JsonParseException e) {
            throw new FuSa.InvalidConfigException("parse error in " + configPath + ": " + e.getMessage());
        }
    }

    //fusa:req REQ-CFG002
    @SuppressWarnings("unchecked")
    public static Config parse(String json) {
        Map<String, Object> root = Json.parseObject(json);

        // configVersion (v1.10) or version (legacy)
        String cfgVer = Json.str(root, "configVersion", "");
        if (cfgVer.isBlank()) cfgVer = Json.str(root, "version", CONFIG_VERSION);
        if (cfgVer.isBlank()) cfgVer = CONFIG_VERSION;

        Map<String, Object> proj = Json.obj(root, "project");
        String name = Json.str(proj, "name", "");
        String projVer = Json.str(proj, "version", "0.1.0");

        // standard: top-level (v1.10) or inside project (legacy)
        String stdStr = Json.str(root, "standard", "");
        if (stdStr.isBlank()) stdStr = Json.str(proj, "standard", "generic");
        Standard std = Standard.of(stdStr);

        // integrity field: top-level (v1.10) or inside project (legacy)
        String asil = Json.str(root, "asil", "");
        if (asil.isBlank()) asil = Json.str(proj, "asil", "");
        String sil = Json.str(root, "sil", "");
        if (sil.isBlank()) sil = Json.str(proj, "sil", "");
        String dal = Json.str(root, "dal", "");
        if (dal.isBlank()) dal = Json.str(proj, "dal", "");

        // artifact is a legacy java-FuSa extension field
        String artifact = Json.str(proj, "artifact", "");

        ProjectConfig pc = new ProjectConfig(name, projVer, std, asil, sil, dal);

        // rules (java-FuSa extension, not in spec)
        Map<String, Object> rulesMap = Json.obj(root, "rules");
        List<String> exclude = new ArrayList<>();
        for (Object o : Json.arr(rulesMap, "exclude")) {
            if (o instanceof String s) exclude.add(s);
        }
        Map<String, String> severity = new LinkedHashMap<>();
        Map<String, Object> sevMap = Json.obj(rulesMap, "severity");
        for (var e : sevMap.entrySet()) {
            if (e.getValue() instanceof String s) severity.put(e.getKey(), s);
        }
        RulesConfig rc = new RulesConfig(Collections.unmodifiableList(exclude),
                Collections.unmodifiableMap(severity));

        // report (java-FuSa extension, not in spec)
        Map<String, Object> repMap = Json.obj(root, "report");
        String fmt = Json.str(repMap, "format", "text");
        String out = Json.str(repMap, "output", "");
        validateFormat(fmt);
        validateSeverityOverrides(severity);

        return new Config(cfgVer, pc, rc, new ReportConfig(fmt, out));
    }

    //fusa:req REQ-CFG003
    private static void validateFormat(String fmt) {
        if (!fmt.equals("text") && !fmt.equals("json") && !fmt.equals("html") && !fmt.equals("sarif")) {
            throw new FuSa.InvalidConfigException("unsupported report format \"" + fmt + "\"");
        }
    }

    private static void validateSeverityOverrides(Map<String, String> severity) {
        for (var e : severity.entrySet()) {
            try { FuSa.Severity.valueOf(e.getValue()); }
            catch (IllegalArgumentException ex) {
                throw new FuSa.InvalidConfigException(
                        "invalid severity override for " + e.getKey() + ": " + e.getValue());
            }
        }
    }

    /** Write §1.2.1 v1.10 schema format. */
    public static void save(Path projectRoot, Config cfg) throws IOException {
        Path path = projectRoot.resolve(CONFIG_FILE);
        var w = new Json.Writer();
        w.objectStart();
        w.field("configVersion", CONFIG_VERSION);
        w.key("project"); w.objectStart();
        w.field("name", cfg.project().name());
        w.field("version", cfg.project().version());
        w.objectEnd();
        w.field("standard", cfg.project().standard().canonicalId());
        if (!cfg.project().asil().isBlank()) w.field("asil", cfg.project().asil());
        if (!cfg.project().sil().isBlank())  w.field("sil",  cfg.project().sil());
        if (!cfg.project().dal().isBlank())  w.field("dal",  cfg.project().dal());
        w.key("rules"); w.objectStart();
        w.key("exclude"); w.arrayStart();
        for (String ex : cfg.rules().exclude()) w.value(ex);
        w.arrayEnd();
        if (!cfg.rules().severity().isEmpty()) {
            w.key("severity"); w.objectStart();
            for (var e : cfg.rules().severity().entrySet()) w.field(e.getKey(), e.getValue());
            w.objectEnd();
        }
        w.objectEnd();
        w.key("report"); w.objectStart();
        w.field("format", cfg.report().format());
        w.fieldIfNonBlank("output", cfg.report().output());
        w.objectEnd();
        w.objectEnd();
        Files.writeString(path, w.toPretty() + "\n");
    }
}
