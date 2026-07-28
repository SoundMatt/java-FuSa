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
 * Software Configuration Index — DO-178C §11.16 (x-FuSa spec §9.3).
 * {@code artifacts[].hash} is a real, {@code sha256:}-prefixed digest of the
 * file's current contents (§2.7 hash conventions) — a placeholder or stale
 * hash would defeat the point of a configuration index.
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

    //fusa:req REQ-SCI001
    public static void generate(Path root, String format) throws IOException {
        if ("markdown".equals(format)) generateMarkdown(root);
        else generateJson(root, SCI_JSON);
    }

    //fusa:req REQ-SCI001
    public static void generateJson(Path root, String outputFile) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "sci");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("standard", "do178c");
        w.key("artifacts"); w.arrayStart();
        for (String item : LIFECYCLE_ITEMS) {
            Path p = root.resolve(item);
            if (!Files.exists(p)) continue;
            // §2.7: a field NAMED "hash" carries "<algo>:<value>" — Release.sha256file already
            // returns the sha256:-prefixed form, unlike the bare-hex "sha256"-named field convention.
            w.objectStart();
            w.field("file", item);
            w.field("hash", Release.sha256file(p));
            w.field("version", FuSa.VERSION);
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        String path = (outputFile == null || outputFile.isBlank()) ? SCI_JSON : outputFile;
        Files.writeString(root.resolve(path), w.toPretty() + "\n");
    }

    static void generateMarkdown(Path root) throws IOException {
        var sb = new StringBuilder();
        sb.append("# Software Configuration Index\n\n");
        sb.append("**Standard:** DO-178C §11.16  \n");
        sb.append("**Generated:** ").append(Instant.now()).append("\n\n");
        sb.append("| File | Hash | Version |\n|---|---|---|\n");
        for (String item : LIFECYCLE_ITEMS) {
            Path p = root.resolve(item);
            if (!Files.exists(p)) continue;
            String hash = Release.sha256file(p);
            sb.append("| `").append(item).append("` | `").append(hash, 0, Math.min(hash.length(), 23))
              .append("...` | ").append(FuSa.VERSION).append(" |\n");
        }
        Files.writeString(root.resolve(SCI_MD), sb.toString());
    }
}
