package com.soundmatt.jfusa.disposition;

import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/** Finding disposition log — accept, defer, or reject ERROR findings. */
public final class Disposition {

    public static final String DISPOSITIONS_FILE = ".fusa-dispositions.json";

    private Disposition() {}

    public record Entry(String ruleId, String file, String action, String rationale,
                        String addedBy, String timestamp) {}

    @SuppressWarnings("unchecked")
    public static List<Entry> load(Path root) throws IOException {
        Path f = root.resolve(DISPOSITIONS_FILE);
        if (!Files.exists(f)) return new ArrayList<>();
        Map<String, Object> doc = Json.parseObject(Files.readString(f));
        List<Entry> entries = new ArrayList<>();
        for (Object item : Json.arr(doc, "dispositions")) {
            if (item instanceof Map<?,?> m) {
                var map = (Map<String, Object>) m;
                entries.add(new Entry(
                        Json.str(map, "ruleId", ""), Json.str(map, "file", ""),
                        Json.str(map, "action", ""), Json.str(map, "rationale", ""),
                        Json.str(map, "addedBy", ""), Json.str(map, "timestamp", "")));
            }
        }
        return entries;
    }

    public static void add(Path root, String ruleId, String file, String action, String rationale)
            throws IOException {
        List<Entry> entries = load(root);
        entries.add(new Entry(ruleId, file, action, rationale,
                System.getProperty("user.name", "unknown"), Instant.now().toString()));
        save(root, entries);
        System.out.println("Disposition added for " + ruleId);
    }

    public static void save(Path root, List<Entry> entries) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-dispositions-1.0");
        w.key("dispositions"); w.arrayStart();
        for (Entry e : entries) {
            w.objectStart();
            w.field("ruleId", e.ruleId()); w.field("file", e.file());
            w.field("action", e.action()); w.field("rationale", e.rationale());
            w.field("addedBy", e.addedBy()); w.field("timestamp", e.timestamp());
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(DISPOSITIONS_FILE), w.toPretty() + "\n");
    }

    public static String list(Path root) throws IOException {
        List<Entry> entries = load(root);
        if (entries.isEmpty()) return "No dispositions recorded.\n";
        var sb = new StringBuilder();
        sb.append(String.format("%-12s %-30s %-10s %s\n", "Rule", "File", "Action", "Rationale"));
        sb.append("-".repeat(80)).append('\n');
        for (Entry e : entries) {
            sb.append(String.format("%-12s %-30s %-10s %s\n",
                    e.ruleId(), e.file().substring(0, Math.min(29, e.file().length())),
                    e.action(), e.rationale().substring(0, Math.min(35, e.rationale().length()))));
        }
        return sb.toString();
    }
}
