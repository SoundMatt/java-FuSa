package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class ConfigTest {

    @TempDir Path tmp;

    @Test
    void defaultConfig_hasName() {
        Config c = Config.defaultConfig("my-project");
        assertEquals("my-project", c.project().name());
        assertEquals("0.1.0", c.project().version());
        assertNotNull(c.rules());
        assertNotNull(c.report());
    }

    @Test
    void saveAndLoad_roundtrip() throws Exception {
        Config original = Config.defaultConfig("roundtrip-test");
        Config.save(tmp, original);
        Config loaded = Config.load(tmp);
        assertEquals(original.project().name(), loaded.project().name());
        assertEquals(original.project().version(), loaded.project().version());
    }

    @Test
    void load_throwsNoConfigException_whenMissing() {
        assertThrows(FuSa.NoConfigException.class, () -> Config.load(tmp));
    }

    @Test
    void defaultConfig_standardIsGeneric() {
        Config c = Config.defaultConfig("test");
        assertEquals(Config.Standard.generic, c.project().standard());
    }

    @Test
    void savedFile_isValid_json() throws Exception {
        Config c = Config.defaultConfig("json-test");
        Config.save(tmp, c);
        Path f = tmp.resolve(".fusa.json");
        assertTrue(f.toFile().exists());
        String content = java.nio.file.Files.readString(f);
        assertTrue(content.contains("\"name\""));
        assertTrue(content.contains("json-test"));
    }
}
