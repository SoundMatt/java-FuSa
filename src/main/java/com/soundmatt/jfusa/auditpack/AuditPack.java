package com.soundmatt.jfusa.auditpack;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.comp.Comp;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.coupling.Coupling;
import com.soundmatt.jfusa.iec62443.Iec62443;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.misra.Misra;
import com.soundmatt.jfusa.release.Release;
import com.soundmatt.jfusa.sas.Sas;
import com.soundmatt.jfusa.sci.Sci;
import com.soundmatt.jfusa.slsa.Slsa;
import com.soundmatt.jfusa.unece.Unece;
import com.soundmatt.jfusa.vuln.Vuln;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
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
    /** x-FuSa spec §8: the audit-pack's own top-level manifest, entry name inside the ZIP. */
    public static final String MANIFEST_ENTRY  = "manifest.json";

    /** §8 MUST: every §1.2 input file and every §1.3 generated file this tool can produce
     *  (except {@link #AUDIT_PACK_FILE} itself, which is excluded from its own contents). */
    private static final List<String> ARTIFACTS = List.of(
            ".fusa.json", ".fusa-reqs.json", ".fusa-hara.json", ".fusa-evidence.json",
            ".fusa-dispositions.json",
            "sbom.json", "provenance.json", "artifact-manifest.json", "qualify-report.json",
            "tara.json", "tara.md",
            "fmea.json", "fmea.csv", "safety-case.json", "safety-case.md",
            "safety-case.mermaid", "check-report.json", "cyber-report.json",
            "iso26262-gap-report.json", "iec61508-gap-report.json",
            "iso21434-gap-report.json", "do178-gap-report.json",
            Iec62443.GAP_REPORT, Unece.GAP_REPORT, Slsa.SLSA_GAP_REPORT, Misra.MISRA_JSON,
            Comp.COMP_JSON, Vuln.VULN_JSON, Coupling.COUPLING_JSON,
            Sci.SCI_JSON, Sas.SAS_JSON, Sas.SAS_MD,
            "boundary.mermaid", "boundary.dot"
    );

    private AuditPack() {}

    /** Backward-compatible entry point; writes the ZIP to {@link #AUDIT_PACK_FILE} in {@code root}. */
    //fusa:req REQ-AUDITPACK001
    public static void generate(Path root) throws IOException {
        generate(root, AUDIT_PACK_FILE);
    }

    /**
     * Bundles every present §1.2/§1.3 evidence artifact plus a spec-required top-level
     * {@code manifest.json} (kind: "audit-manifest") into a ZIP at {@code output}
     * (resolved against {@code root}), creating the parent directory if needed.
     */
    //fusa:req REQ-AUDITPACK002
    public static void generate(Path root, String output) throws IOException {
        List<String> included = new ArrayList<>();
        List<Path> toBundle = new ArrayList<>();
        for (String art : ARTIFACTS) {
            Path p = root.resolve(art);
            if (Files.exists(p)) { toBundle.add(p); included.add(art); }
        }

        String manifestJson = buildAuditManifest(root, included, toBundle);

        Path zipPath = root.resolve(output);
        if (zipPath.getParent() != null) Files.createDirectories(zipPath.getParent());

        try (OutputStream fos = Files.newOutputStream(zipPath);
             ZipOutputStream zos = new ZipOutputStream(fos)) {
            // §8 MUST: top-level manifest.json (kind: "audit-manifest"), distinct from
            // release's artifact-manifest.json (which is bundled as an ordinary evidence
            // file above, if present, not misnamed as this manifest).
            ZipEntry manifestEntry = new ZipEntry(MANIFEST_ENTRY);
            manifestEntry.setLastModifiedTime(FileTime.from(Instant.now()));
            zos.putNextEntry(manifestEntry);
            zos.write(manifestJson.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
            for (Path p : toBundle) {
                addToZip(zos, p, root.relativize(p).toString());
            }
        }

        System.out.println("Audit pack written to " + output + " (" + (included.size() + 1) + " files)");
    }

    /** Builds the §8 audit-manifest JSON body (not written to disk — only into the ZIP). */
    private static String buildAuditManifest(Path root, List<String> included, List<Path> toBundle)
            throws IOException {
        String module;
        try {
            module = Config.load(root).project().name();
        } catch (FuSa.NoConfigException e) {
            module = "unknown";
        }

        var w = new Json.Writer();
        w.objectStart();
        // §3.1 common header
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "audit-manifest");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("module", module);
        // §8 body — files[] with path/size/sha256 (bare lowercase hex)
        w.key("files"); w.arrayStart();
        for (int i = 0; i < toBundle.size(); i++) {
            Path p = toBundle.get(i);
            String fullHash = Release.sha256file(p);
            String bareHex = fullHash.startsWith("sha256:") ? fullHash.substring(7) : fullHash;
            w.objectStart();
            w.field("path", included.get(i));
            w.field("size", Files.size(p));
            w.field("sha256", bareHex);
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        return w.toPretty() + "\n";
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
