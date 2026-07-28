package com.soundmatt.jfusa;

import com.soundmatt.jfusa.sci.Sci;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SciTest {

    @TempDir Path tmp;

    @Test
    //fusa:test REQ-SCI001
    void generateJson_usesHashFieldNameWithSha256Prefix() throws Exception {
        Files.writeString(tmp.resolve(".fusa.json"), "{}");
        Sci.generateJson(tmp, "");
        String json = Files.readString(tmp.resolve(Sci.SCI_JSON));
        assertTrue(json.contains("\"artifacts\""));
        assertTrue(json.contains("\"file\""));
        assertTrue(json.contains("\"hash\": \"sha256:"), "hash-named field must be sha256:-prefixed (§2.7)");
        assertFalse(json.contains("\"sha256\":"), "no bare \"sha256\"-named field should remain");
    }

    @Test
    //fusa:test REQ-SCI001
    void generateJson_omitsMissingFiles_ratherThanEmptyPlaceholderHash() throws Exception {
        // no files at all present in tmp
        Sci.generateJson(tmp, "");
        String json = Files.readString(tmp.resolve(Sci.SCI_JSON));
        assertFalse(json.contains("\"hash\": \"\""), "a missing file must never produce a placeholder empty hash");
    }

    @Test
    //fusa:test REQ-SCI001
    void generateJson_respectsCustomOutputPath() throws Exception {
        Files.writeString(tmp.resolve(".fusa.json"), "{}");
        Sci.generateJson(tmp, "custom-sci.json");
        assertTrue(Files.exists(tmp.resolve("custom-sci.json")));
    }

    @Test
    //fusa:test REQ-SCI001
    void generate_markdownFormat() throws Exception {
        Files.writeString(tmp.resolve(".fusa.json"), "{}");
        Sci.generate(tmp, "markdown");
        assertTrue(Files.exists(tmp.resolve(Sci.SCI_MD)));
    }
}
