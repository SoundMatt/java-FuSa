package com.soundmatt.jfusa.sci;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.release.Release;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * Software Configuration Index — SHA-256 checksums of lifecycle data items (DO-178C §11.16).
 */
public final class Sci {

    public static final String SCI_JSON = "sci.json";
    public static final String SCI_MD   = "sci.md";

    private static final List<String> LIFECYCLE_ITEMS = List.of(
            "pom.xml", ".fusa.json", ".fusa-reqs.json", "CLAUDE.md",
            "qualify-report.json", "sbom.json", "provenance.json",
            ".fusa-evidence.json", "tara.json", "fmea.json",
            "safety-case.json", "do178-gap-report.json"
    );

    private Sci() {}

    public static void generate(Path root, String format) throws IOException {
        if ("markdown".equals(format)) generateMarkdown(root);
        else generateJson(root);
    }

    static void generateJson(Path root) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-sci-1.0");
        w.field("standard", "DO-178C §11.16");
        w.field("timestamp", Instant.now().toString());
        w.key("items"); w.arrayStart();
        for (String item : LIFECYCLE_ITEMS) {
            Path p = root.resolve(item);
            w.objectStart();
            w.field("path", item);
            if (Files.exists(p)) {
                w.field("sha256", Release.sha256file(p));
                w.field("present", true);
            } else {
                w.field("sha256", "");
                w.field("present", false);
            }
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(SCI_JSON), w.toPretty() + "\n");
    }

    static void generateMarkdown(Path root) throws IOException {
        var sb = new StringBuilder();
        sb.append("# Software Configuration Index\n\n");
        sb.append("**Standard:** DO-178C §11.16  \n");
        sb.append("**Generated:** ").append(Instant.now()).append("\n\n");
        sb.append("| Item | Present | SHA-256 |\n|---|---|---|\n");
        for (String item : LIFECYCLE_ITEMS) {
            Path p = root.resolve(item);
            String hash = Files.exists(p) ? "`" + Release.sha256file(p).substring(7, 23) + "...`" : "—";
            sb.append("| `").append(item).append("` | ").append(Files.exists(p) ? "✓" : "✗")
              .append(" | ").append(hash).append(" |\n");
        }
        Files.writeString(root.resolve(SCI_MD), sb.toString());
    }
}
