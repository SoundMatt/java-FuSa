package com.soundmatt.jfusa.config;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Project configuration for java-FuSa.
 *
 * <p>A project is configured via a {@code .fusa.json} file at the project root.
 * Use {@link #load(Path)} to read an existing file, {@link #defaultConfig(String)} to
 * build a starter config, and {@link #save(Path, Config)} to write to disk.
 */
public final class Config {

    /** Conventional name of the java-FuSa configuration file. */
    public static final String CONFIG_FILE = ".fusa.json";

    // ── Standard identifiers ─────────────────────────────────────────────────

    //fusa:req REQ-NF003
    public enum Standard {
        ISO26262, IEC61508, ISO21434, DO178C, generic;

        public static Standard of(String s) {
            if (s == null || s.isBlank()) return generic;
            try { return Standard.valueOf(s.toUpperCase()); } catch (IllegalArgumentException e) { return generic; }
        }
    }

    // ── Value types ───────────────────────────────────────────────────────────

    public record ProjectConfig(
            String name,
            String artifact,
            Standard standard,
            String asil,
            String sil
    ) {
        public ProjectConfig(String name) {
            this(name, "", Standard.generic, "", "");
        }
    }

    public record RulesConfig(
            List<String> exclude,
            Map<String, String> severity
    ) {
        public RulesConfig() { this(List.of(), Map.of()); }
    }

    public record ReportConfig(
            String format,
            String output
    ) {
        public ReportConfig() { this("text", ""); }
    }

    // ── Config record ─────────────────────────────────────────────────────────

    private final String version;
    private final ProjectConfig project;
    private final RulesConfig rules;
    private final ReportConfig report;

    public Config(String version, ProjectConfig project, RulesConfig rules, ReportConfig report) {
        this.version = version;
        this.project = project;
        this.rules = rules;
        this.report = report;
    }

    public String version()    { return version; }
    public ProjectConfig project() { return project; }
    public RulesConfig rules() { return rules; }
    public ReportConfig report() { return report; }

    // ── Factory methods ───────────────────────────────────────────────────────

    //fusa:req REQ-CFG005
    public static Config defaultConfig(String name) {
        return new Config("1",
                new ProjectConfig(name, "", Standard.generic, "", ""),
                new RulesConfig(),
                new ReportConfig());
    }

    // ── Load ──────────────────────────────────────────────────────────────────

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
    static Config parse(String json) {
        Map<String, Object> root = Json.parseObject(json);

        String version = Json.str(root, "version", "");
        if (version.isBlank()) {
            throw new FuSa.InvalidConfigException("missing version field");
        }

        Map<String, Object> proj = Json.obj(root, "project");
        String asil = Json.str(proj, "asil", "");
        String sil  = Json.str(proj, "sil", "");
        Standard std = Standard.of(Json.str(proj, "standard", "generic"));
        ProjectConfig pc = new ProjectConfig(
                Json.str(proj, "name", ""),
                Json.str(proj, "artifact", ""),
                std, asil, sil);

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

        Map<String, Object> repMap = Json.obj(root, "report");
        String fmt = Json.str(repMap, "format", "text");
        String out = Json.str(repMap, "output", "");
        validateFormat(fmt);
        validateSeverityOverrides(severity);

        return new Config(version, pc, rc, new ReportConfig(fmt, out));
    }

    //fusa:req REQ-CFG003
    private static void validateFormat(String fmt) {
        if (!fmt.equals("text") && !fmt.equals("json") && !fmt.equals("html") && !fmt.equals("sarif")) {
            throw new FuSa.InvalidConfigException("unsupported report format \"" + fmt + "\"");
        }
    }

    //fusa:req REQ-CFG008
    private static void validateSeverityOverrides(Map<String, String> severity) {
        for (var e : severity.entrySet()) {
            String sev = e.getValue();
            if (!sev.equals("ERROR") && !sev.equals("WARNING") && !sev.equals("INFO")) {
                throw new FuSa.InvalidConfigException("rule " + e.getKey() +
                        " has invalid severity override \"" + sev + "\" (must be ERROR, WARNING, or INFO)");
            }
        }
    }

    // ── Save ──────────────────────────────────────────────────────────────────

    //fusa:req REQ-CFG006
    public static void save(Path projectRoot, Config cfg) throws IOException {
        Path path = projectRoot.resolve(CONFIG_FILE);
        var w = new Json.Writer();
        w.objectStart();
        w.field("version", cfg.version());
        w.key("project"); w.objectStart();
        w.field("name", cfg.project().name());
        w.field("artifact", cfg.project().artifact());
        w.field("standard", cfg.project().standard().name());
        if (!cfg.project().asil().isBlank()) w.field("asil", cfg.project().asil());
        if (!cfg.project().sil().isBlank())  w.field("sil",  cfg.project().sil());
        w.objectEnd();
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
