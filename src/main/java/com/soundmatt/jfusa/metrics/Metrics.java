package com.soundmatt.jfusa.metrics;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.report.Report;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/** Track safety metrics over time (finding counts, coverage %, requirement density). */
public final class Metrics {

    public static final String METRICS_FILE = ".fusa-metrics.json";

    private Metrics() {}

    public static void record(Path root, Report report) throws IOException {
        List<Map<String, Object>> history = loadHistory(root);
        var entry = new LinkedHashMap<String, Object>();
        entry.put("timestamp", Instant.now().toString());
        entry.put("errors", report.errors().size());
        entry.put("warnings", report.warnings().size());
        entry.put("infos", report.infos().size());
        entry.put("total", report.result().findings().size());
        entry.put("status", report.result().hasErrors() ? "FAIL" : "PASS");
        history.add(entry);
        saveHistory(root, history);
        System.out.println("Metrics recorded: " + report.summary());
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> loadHistory(Path root) throws IOException {
        Path f = root.resolve(METRICS_FILE);
        if (!Files.exists(f)) return new ArrayList<>();
        try {
            Map<String, Object> doc = Json.parseObject(Files.readString(f));
            List<Object> arr = Json.arr(doc, "history");
            List<Map<String, Object>> result = new ArrayList<>();
            for (Object item : arr) {
                if (item instanceof Map<?,?> m) result.add((Map<String, Object>) m);
            }
            return result;
        } catch (Exception e) { return new ArrayList<>(); }
    }

    static void saveHistory(Path root, List<Map<String, Object>> history) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-metrics-1.0");
        w.key("history"); w.arrayStart();
        for (Map<String, Object> e : history) {
            w.objectStart();
            for (var kv : e.entrySet()) {
                if (kv.getValue() instanceof String s) w.field(kv.getKey(), s);
                else if (kv.getValue() instanceof Number n) w.field(kv.getKey(), n.longValue());
            }
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(METRICS_FILE), w.toPretty() + "\n");
    }

    public static String show(Path root) throws IOException {
        List<Map<String, Object>> history = loadHistory(root);
        if (history.isEmpty()) return "No metrics recorded yet. Run 'jfusa metrics record'\n";
        var sb = new StringBuilder();
        sb.append("Safety Metrics History\n").append("=".repeat(60)).append('\n');
        sb.append(String.format("%-28s %6s %8s %5s %6s\n", "Timestamp", "Errors", "Warnings", "Info", "Status"));
        sb.append("-".repeat(60)).append('\n');
        for (Map<String, Object> e : history) {
            sb.append(String.format("%-28s %6s %8s %5s %6s\n",
                    e.getOrDefault("timestamp", ""), e.getOrDefault("errors", 0),
                    e.getOrDefault("warnings", 0), e.getOrDefault("infos", 0),
                    e.getOrDefault("status", "")));
        }
        return sb.toString();
    }
}
