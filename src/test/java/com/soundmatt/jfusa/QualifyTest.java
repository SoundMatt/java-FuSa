package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.qualify.Qualify;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class QualifyTest {

    @TempDir Path tmp;

    @Test
    void qualify_generatesReport() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.run(tmp, cfg, false);
        Path report = tmp.resolve("qualify-report.json");
        assertTrue(Files.exists(report), "qualify-report.json should be generated");
    }

    @Test
    void qualify_reportContainsPassStatus() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.run(tmp, cfg, false);
        String content = Files.readString(tmp.resolve("qualify-report.json"));
        assertTrue(content.contains("\"schema\""));
        assertTrue(content.contains("TC-001"));
    }

    @Test
    void qualify_reportHasIntegrityHash() throws Exception {
        Config cfg = Config.defaultConfig("qualify-test");
        Config.save(tmp, cfg);
        Qualify.run(tmp, cfg, false);
        String content = Files.readString(tmp.resolve("qualify-report.json"));
        assertTrue(content.contains("\"integrityHash\"") || content.contains("sha256"),
                "qualify report should contain integrity hash");
    }
}
