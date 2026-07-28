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
}
