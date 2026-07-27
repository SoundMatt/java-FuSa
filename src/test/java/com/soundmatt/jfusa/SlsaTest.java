package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.release.Release;
import com.soundmatt.jfusa.slsa.Slsa;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises the SLSA001/002/003 engine rules directly (beyond the gap-report command). */
class SlsaTest {

    @TempDir Path tmp;

    //fusa:test REQ-SLSA003
    @Test
    void slsa001_firesWhenNoProvenance_silentWhenPresent() throws Exception {
        Slsa.activate();
        Config cfg = Config.defaultConfig("slsa001-test");
        Engine.Result before = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("SLSA001"));
        assertTrue(before.findings().stream().anyMatch(f -> f.ruleId().equals("SLSA001")));

        Files.writeString(tmp.resolve(Release.PROVENANCE_FILE), "{}");
        Engine.Result after = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("SLSA001"));
        assertTrue(after.findings().stream().noneMatch(f -> f.ruleId().equals("SLSA001")));
    }

    //fusa:test REQ-SLSA004
    @Test
    void slsa002_firesWhenNoCodeowners_silentWhenPresent() throws Exception {
        Slsa.activate();
        Config cfg = Config.defaultConfig("slsa002-test");
        Engine.Result before = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("SLSA002"));
        assertTrue(before.findings().stream().anyMatch(f -> f.ruleId().equals("SLSA002")));

        Files.writeString(tmp.resolve("CODEOWNERS"), "* @soundmatt");
        Engine.Result after = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("SLSA002"));
        assertTrue(after.findings().stream().noneMatch(f -> f.ruleId().equals("SLSA002")));
    }

    //fusa:test REQ-SLSA005
    @Test
    void slsa003_firesWhenNoSbom_silentWhenPresent() throws Exception {
        Slsa.activate();
        Config cfg = Config.defaultConfig("slsa003-test");
        Engine.Result before = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("SLSA003"));
        assertTrue(before.findings().stream().anyMatch(f -> f.ruleId().equals("SLSA003")));

        Files.writeString(tmp.resolve(Release.SBOM_FILE), "{}");
        Engine.Result after = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("SLSA003"));
        assertTrue(after.findings().stream().noneMatch(f -> f.ruleId().equals("SLSA003")));
    }
}
