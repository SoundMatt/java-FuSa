package com.soundmatt.jfusa;

import com.soundmatt.jfusa.auditpack.AuditPack;
import com.soundmatt.jfusa.config.Config;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.*;

class AuditPackTest {

    @TempDir Path tmp;

    private void initProject() throws Exception {
        Config cfg = Config.defaultConfig("auditpack-test");
        Config.save(tmp, cfg);
        Files.writeString(tmp.resolve("sbom.json"), "{\"kind\":\"sbom\"}");
    }

    @Test
    //fusa:test REQ-AUDITPACK002
    void generate_honorsExplicitOutputPath() throws Exception {
        initProject();
        AuditPack.generate(tmp, "custom/ap.zip");
        assertTrue(Files.exists(tmp.resolve("custom/ap.zip")),
                "explicit output path should be honored, including auto-created parent dirs");
        assertFalse(Files.exists(tmp.resolve(AuditPack.AUDIT_PACK_FILE)),
                "default audit-pack.zip must not also be written when an explicit output is given");
    }

    @Test
    //fusa:test REQ-AUDITPACK003
    void generate_zipContainsAuditManifestNotArtifactManifest() throws Exception {
        initProject();
        AuditPack.generate(tmp);
        Path zipPath = tmp.resolve(AuditPack.AUDIT_PACK_FILE);
        assertTrue(Files.exists(zipPath));

        try (ZipFile zf = new ZipFile(zipPath.toFile())) {
            ZipEntry manifestEntry = zf.getEntry(AuditPack.MANIFEST_ENTRY);
            assertNotNull(manifestEntry, "ZIP must contain a top-level manifest.json entry");
            assertNull(zf.getEntry("artifact-manifest.json"),
                    "audit-pack must not synthesize a bare artifact-manifest.json as a side effect");

            String content;
            try (InputStream in = zf.getInputStream(manifestEntry)) {
                content = new String(in.readAllBytes());
            }
            assertTrue(content.contains("\"kind\": \"audit-manifest\"") || content.contains("\"kind\":\"audit-manifest\""),
                    "manifest.json must declare kind=audit-manifest per x-FuSa spec §8, not artifact-manifest");
            assertTrue(content.contains("\"files\""), "manifest.json must list files[]");
            assertTrue(content.contains("\"size\""), "manifest.json files[] entries must carry a size field");
            assertTrue(content.contains("sbom.json"), "manifest.json must list the bundled sbom.json");
        }
    }

    @Test
    //fusa:test REQ-AUDITPACK002
    void generate_bundlesAllSpecEvidenceFilesAndExcludesNonSpecFiles() throws Exception {
        initProject();
        // §1.3-listed generated evidence this tool can itself produce, but that were
        // missing from the old hardcoded ARTIFACTS list.
        Files.writeString(tmp.resolve("comp-report.json"), "{}");
        Files.writeString(tmp.resolve("vuln.json"), "{}");
        Files.writeString(tmp.resolve("coupling-report.json"), "{}");
        Files.writeString(tmp.resolve("sci.json"), "{}");
        Files.writeString(tmp.resolve("sas.json"), "{}");
        Files.writeString(tmp.resolve("sas.md"), "# sas");
        Files.writeString(tmp.resolve("iec62443-gap-report.json"), "{}");
        Files.writeString(tmp.resolve("unece-gap-report.json"), "{}");
        Files.writeString(tmp.resolve("slsa-gap-report.json"), "{}");
        Files.writeString(tmp.resolve("misra-java-gap-report.json"), "{}");
        // Not §1.2/§1.3 evidence — must NOT be swept into the pack.
        Files.writeString(tmp.resolve("CHANGELOG.md"), "# changelog");
        Files.writeString(tmp.resolve("SECURITY.md"), "# security");

        AuditPack.generate(tmp);
        Path zipPath = tmp.resolve(AuditPack.AUDIT_PACK_FILE);
        try (ZipFile zf = new ZipFile(zipPath.toFile())) {
            for (String expected : new String[]{
                    "comp-report.json", "vuln.json", "coupling-report.json", "sci.json",
                    "sas.json", "sas.md", "iec62443-gap-report.json", "unece-gap-report.json",
                    "slsa-gap-report.json", "misra-java-gap-report.json"}) {
                assertNotNull(zf.getEntry(expected), expected + " is §1.3 evidence and must be bundled");
            }
            assertNull(zf.getEntry("CHANGELOG.md"), "CHANGELOG.md is not §1.2/§1.3 evidence");
            assertNull(zf.getEntry("SECURITY.md"), "SECURITY.md is not §1.2/§1.3 evidence");
        }
    }
}
