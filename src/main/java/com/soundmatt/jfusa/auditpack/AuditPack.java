package com.soundmatt.jfusa.auditpack;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.release.Release;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Bundles all evidence artifacts into a single ZIP for auditors, with a hashed manifest.
 */
public final class AuditPack {

    public static final String AUDIT_PACK_FILE = "audit-pack.zip";
    public static final String MANIFEST_FILE   = "artifact-manifest.json";

    private static final List<String> ARTIFACTS = List.of(
            ".fusa.json", ".fusa-reqs.json", ".fusa-hara.json", ".fusa-evidence.json",
            ".fusa-dispositions.json",
            "sbom.json", "provenance.json", "qualify-report.json",
            "tara.json", "tara.md",
            "fmea.json", "fmea.csv", "safety-case.json", "safety-case.md",
            "safety-case.mermaid", "check-report.json", "cyber-report.json",
            "iso26262-gap-report.json", "iec61508-gap-report.json",
            "iso21434-gap-report.json", "do178-gap-report.json",
            "boundary.mermaid", "boundary.dot", "CHANGELOG.md", "SECURITY.md"
    );

    private AuditPack() {}

    //fusa:req REQ-AUDITPACK001
    public static void generate(Path root) throws IOException {
        List<String> included = new ArrayList<>();
        List<Path> toBundle = new ArrayList<>();
        for (String art : ARTIFACTS) {
            Path p = root.resolve(art);
            if (Files.exists(p)) { toBundle.add(p); included.add(art); }
        }

        // Write manifest first
        Release.generateManifest(root, included);

        // Bundle into ZIP
        Path zipPath = root.resolve(AUDIT_PACK_FILE);
        try (OutputStream fos = Files.newOutputStream(zipPath);
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            // Add manifest
            addToZip(zos, root.resolve(MANIFEST_FILE), "artifact-manifest.json");
            for (Path p : toBundle) {
                addToZip(zos, p, root.relativize(p).toString());
            }
        }

        System.out.println("Audit pack written to " + AUDIT_PACK_FILE + " (" + (included.size() + 1) + " files)");
    }

    static void addToZip(ZipOutputStream zos, Path file, String entryName) throws IOException {
        if (!Files.exists(file)) return;
        ZipEntry entry = new ZipEntry(entryName);
        entry.setLastModifiedTime(Files.getLastModifiedTime(file));
        zos.putNextEntry(entry);
        Files.copy(file, zos);
        zos.closeEntry();
    }
}
