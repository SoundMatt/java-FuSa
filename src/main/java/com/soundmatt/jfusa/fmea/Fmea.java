package com.soundmatt.jfusa.fmea;

import com.soundmatt.jfusa.FuSa;
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
 * Design FMEA (dFMEA) generation — derives failure modes and effects from public Java methods.
 * Produces fmea.json and fmea.csv.
 */
public final class Fmea {

    public static final String FMEA_JSON = "fmea.json";
    public static final String FMEA_CSV  = "fmea.csv";

    private static final Pattern PUBLIC_METHOD = Pattern.compile(
            "public\\s+(?!class|interface|enum|record)(?:static\\s+)?\\w+\\s+(\\w+)\\s*\\(([^)]*)\\)");

    private Fmea() {}

    public record FmeaEntry(
            String id, String component, String method, String failureMode,
            String effect, String severity, String occurrence, String detection, String rpn) {}

    public static List<FmeaEntry> derive(Path root, com.soundmatt.jfusa.config.Config cfg) throws IOException {
        List<FmeaEntry> entries = new ArrayList<>();
        int id = 1;
        for (Path f : LintRules.javaFiles(root, cfg)) {
            String rel = root.relativize(f).toString();
            String component = f.getFileName().toString().replace(".java", "");
            List<String> lines = LintRules.readLines(f);
            for (int i = 0; i < lines.size(); i++) {
                Matcher m = PUBLIC_METHOD.matcher(lines.get(i));
                if (m.find()) {
                    String method = m.group(1);
                    if (method.equals("main") || method.equals("equals") || method.equals("hashCode")) continue;
                    String sev = methodSeverity(method);
                    entries.add(new FmeaEntry(
                            "FMEA-" + String.format("%03d", id++),
                            component, method,
                            "Returns incorrect value / throws unexpected exception",
                            "Safety function output invalid — system may not detect fault condition",
                            sev, "Low", "Code review + unit test coverage", rpn(sev)));
                }
            }
        }
        return entries;
    }

    static String methodSeverity(String name) {
        String lower = name.toLowerCase();
        if (lower.contains("safe") || lower.contains("shutdown") || lower.contains("stop") ||
            lower.contains("halt") || lower.contains("reset")) return "Critical";
        if (lower.contains("check") || lower.contains("validate") || lower.contains("verify") ||
            lower.contains("monitor") || lower.contains("detect")) return "Significant";
        return "Moderate";
    }

    static String rpn(String sev) {
        return switch (sev) {
            case "Critical" -> "High";
            case "Significant" -> "Medium";
            default -> "Low";
        };
    }

    public static void generate(Path root, com.soundmatt.jfusa.config.Config cfg) throws IOException {
        List<FmeaEntry> entries = derive(root, cfg);
        writeJson(root, entries);
        writeCsv(root, entries);
    }

    static void writeJson(Path root, List<FmeaEntry> entries) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "fmea-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.key("entries"); w.arrayStart();
        for (FmeaEntry e : entries) {
            w.objectStart();
            w.field("id", e.id()); w.field("component", e.component());
            w.field("method", e.method()); w.field("failureMode", e.failureMode());
            w.field("effect", e.effect()); w.field("severity", e.severity());
            w.field("occurrence", e.occurrence()); w.field("detection", e.detection());
            w.field("rpn", e.rpn());
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(FMEA_JSON), w.toPretty() + "\n");
    }

    static void writeCsv(Path root, List<FmeaEntry> entries) throws IOException {
        var sb = new StringBuilder();
        sb.append("ID,Component,Method,Failure Mode,Effect,Severity,Occurrence,Detection,RPN\n");
        for (FmeaEntry e : entries) {
            sb.append(csv(e.id())).append(',').append(csv(e.component())).append(',')
              .append(csv(e.method())).append(',').append(csv(e.failureMode())).append(',')
              .append(csv(e.effect())).append(',').append(csv(e.severity())).append(',')
              .append(csv(e.occurrence())).append(',').append(csv(e.detection())).append(',')
              .append(csv(e.rpn())).append('\n');
        }
        Files.writeString(root.resolve(FMEA_CSV), sb.toString());
    }

    static String csv(String s) { return "\"" + s.replace("\"", "\"\"") + "\""; }
}
