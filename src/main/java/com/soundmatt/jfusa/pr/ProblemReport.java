package com.soundmatt.jfusa.pr;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Problem report log — CRUD + PR001 engine rule (DO-178C §11.17).
 */
public final class ProblemReport {

    public static final String PR_FILE = ".fusa-problems.json";

    private ProblemReport() {}

    public record Entry(String id, String title, String severity, String status,
                        String resolution, String timestamp) {}

    public static void init(Path root) throws IOException {
        if (Files.exists(root.resolve(PR_FILE))) { System.out.println("Problem report log already exists."); return; }
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "problem-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("standard", "do178c");
        w.key("problems"); w.arrayStart(); w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(PR_FILE), w.toPretty() + "\n");
        System.out.println("Problem report log created: " + PR_FILE);
    }

    public static void add(Path root, String id, String title, String severity) throws IOException {
        List<Entry> entries = load(root);
        entries.add(new Entry(id, title, severity, "open", "", Instant.now().toString()));
        save(root, entries);
        System.out.println("Problem report " + id + " added.");
    }

    public static void close(Path root, String id, String resolution) throws IOException {
        List<Entry> entries = load(root);
        List<Entry> updated = new ArrayList<>();
        for (Entry e : entries) {
            if (e.id().equals(id)) updated.add(new Entry(e.id(), e.title(), e.severity(), "closed", resolution, e.timestamp()));
            else updated.add(e);
        }
        save(root, updated);
        System.out.println("Problem report " + id + " closed.");
    }

    @SuppressWarnings("unchecked")
    public static List<Entry> load(Path root) throws IOException {
        Path f = root.resolve(PR_FILE);
        if (!Files.exists(f)) return new ArrayList<>();
        try {
            Map<String, Object> doc = Json.parseObject(Files.readString(f));
            List<Entry> result = new ArrayList<>();
            for (Object item : Json.arr(doc, "problems")) {
                if (item instanceof Map<?,?> m) {
                    var map = (Map<String, Object>) m;
                    result.add(new Entry(
                            Json.str(map, "id", ""), Json.str(map, "title", ""),
                            Json.str(map, "severity", ""), Json.str(map, "status", ""),
                            Json.str(map, "resolution", ""), Json.str(map, "timestamp", "")));
                }
            }
            return result;
        } catch (Exception e) { return new ArrayList<>(); }
    }

    public static void save(Path root, List<Entry> entries) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "problem-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("standard", "do178c");
        w.key("problems"); w.arrayStart();
        for (Entry e : entries) {
            w.objectStart();
            w.field("id", e.id()); w.field("title", e.title());
            w.field("severity", e.severity()); w.field("status", e.status());
            w.field("resolution", e.resolution()); w.field("timestamp", e.timestamp());
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(PR_FILE), w.toPretty() + "\n");
    }

    public static String list(Path root) throws IOException {
        List<Entry> entries = load(root);
        if (entries.isEmpty()) return "No problem reports.\n";
        var sb = new StringBuilder();
        sb.append(String.format("%-10s %-35s %-10s %-8s\n", "ID", "Title", "Severity", "Status"));
        sb.append("-".repeat(70)).append('\n');
        for (Entry e : entries) {
            sb.append(String.format("%-10s %-35s %-10s %-8s\n",
                    e.id(), e.title().substring(0, Math.min(34, e.title().length())),
                    e.severity(), e.status()));
        }
        return sb.toString();
    }
}
