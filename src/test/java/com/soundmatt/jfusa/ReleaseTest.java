package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.release.Release;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class ReleaseTest {

    @TempDir Path tmp;

    //fusa:test REQ-RELEASE003
    @Test
    void release_generatesSbom() throws Exception {
        Config cfg = Config.defaultConfig("release-test");
        Config.save(tmp, cfg);
        Files.writeString(tmp.resolve("pom.xml"), "<project><version>0.1.0</version></project>");
        Release.generateSBOM(tmp, cfg);
        Path sbom = tmp.resolve(Release.SBOM_FILE);
        assertTrue(Files.exists(sbom), "sbom.json should be generated");
        String content = Files.readString(sbom);
        assertTrue(content.contains("x-FuSa") || content.contains("sbom") || content.contains("\"kind\""),
                "SBOM should be x-FuSa SBOM format");
    }

    //fusa:test REQ-RELEASE004
    @Test
    void release_generatesProvenance() throws Exception {
        Config cfg = Config.defaultConfig("release-test");
        Config.save(tmp, cfg);
        Files.writeString(tmp.resolve("pom.xml"), "<project><version>0.1.0</version></project>");
        Release.generateProvenance(tmp, cfg);
        Path prov = tmp.resolve(Release.PROVENANCE_FILE);
        assertTrue(Files.exists(prov), "provenance.json should be generated");
        String content = Files.readString(prov);
        assertTrue(content.contains("slsa") || content.contains("SLSA") || content.contains("builder"),
                "Provenance should be SLSA in-toto format");
    }

    //fusa:test REQ-RELEASE005
    @Test
    void release_run_generatesBothArtifacts() throws Exception {
        Config cfg = Config.defaultConfig("release-test");
        Config.save(tmp, cfg);
        Files.writeString(tmp.resolve("pom.xml"), "<project><version>0.1.0</version></project>");
        Release.run(tmp, cfg);
        assertTrue(Files.exists(tmp.resolve(Release.SBOM_FILE)));
        assertTrue(Files.exists(tmp.resolve(Release.PROVENANCE_FILE)));
    }

    //fusa:test REQ-RELEASE005
    @Test
    void release_generateManifest_hashesListedArtifacts() throws Exception {
        Path artifact = tmp.resolve("dummy.jar");
        Files.writeString(artifact, "fake jar contents");
        Release.generateManifest(tmp, java.util.List.of("dummy.jar"));
        Path manifest = tmp.resolve(Release.MANIFEST_FILE);
        assertTrue(Files.exists(manifest));
        String content = Files.readString(manifest);
        assertTrue(content.contains("dummy.jar"));
        assertTrue(content.contains("\"sha256\""));
    }

    //fusa:test REQ-RELEASE006
    @Test
    void sha256file_isHexString() throws Exception {
        Path f = tmp.resolve("test.txt");
        Files.writeString(f, "hello world");
        String hash = Release.sha256file(f);
        assertNotNull(hash);
        assertTrue(hash.matches("[0-9a-f]{64}") || hash.matches("sha256:[0-9a-f]{64}"),
                "SHA-256 should be 64 hex chars (optionally prefixed)");
    }

    //fusa:test REQ-RELEASE006
    @Test
    void sha256file_different_for_different_content() throws Exception {
        Path a = tmp.resolve("a.txt"); Path b = tmp.resolve("b.txt");
        Files.writeString(a, "content A"); Files.writeString(b, "content B");
        assertNotEquals(Release.sha256file(a), Release.sha256file(b));
    }
}
