package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class ConfigTest {

    @TempDir Path tmp;

    //fusa:test REQ-CFG005
    //fusa:test REQ-CFG010
    @Test
    void defaultConfig_hasName() {
        Config c = Config.defaultConfig("my-project");
        assertEquals("my-project", c.project().name());
        assertEquals("1.0", c.configVersion());
        assertEquals(c.configVersion(), c.version()); // version() is a legacy alias
        assertNotNull(c.rules());
        assertNotNull(c.report());
    }

    //fusa:test REQ-CFG001
    //fusa:test REQ-CFG002
    //fusa:test REQ-CFG011
    //fusa:test REQ-CFG012
    @Test
    void saveAndLoad_roundtrip() throws Exception {
        Config original = Config.defaultConfig("roundtrip-test");
        Config.save(tmp, original);
        Config loaded = Config.load(tmp);
        assertEquals(original.project().name(), loaded.project().name());
        assertEquals(original.configVersion(), loaded.configVersion());
        assertEquals(original.rules().exclude(), loaded.rules().exclude());
        assertEquals(original.report().format(), loaded.report().format());
    }

    //fusa:test REQ-ERR001
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

    //fusa:test REQ-CFG003
    @Test
    void parse_throwsInvalidConfigException_onUnsupportedFormat() {
        String json = "{\"project\":{\"name\":\"x\"},\"report\":{\"format\":\"yaml\"}}";
        assertThrows(FuSa.InvalidConfigException.class, () -> Config.parse(json));
    }

    //fusa:test REQ-NF003
    @Test
    void standard_canonicalIdIsLowercase() {
        assertEquals("iso26262", Config.Standard.ISO26262.canonicalId());
        assertEquals("do178c", Config.Standard.DO178C.canonicalId());
        assertEquals(Config.Standard.ISO26262, Config.Standard.of("ISO26262"));
        assertEquals(Config.Standard.ISO26262, Config.Standard.of("iso26262"));
        assertEquals(Config.Standard.generic, Config.Standard.of("not-a-real-standard"));
    }
}
