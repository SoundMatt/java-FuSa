package com.soundmatt.jfusa;

import com.soundmatt.jfusa.sign.Sign;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class SignTest {

    @TempDir Path tmp;

    @Test
    void generateKey_createsKeyFile() throws Exception {
        Path key = tmp.resolve("test.key");
        Sign.generateKey(key);
        assertTrue(Files.exists(key));
        assertTrue(Files.size(key) > 0);
    }

    @Test
    void signAndVerify_roundtrip() throws Exception {
        Path file = tmp.resolve("test.json");
        Path key  = tmp.resolve("test.key");
        Files.writeString(file, "{\"data\":\"hello\"}");
        Sign.generateKey(key);
        Sign.sign(file, key);
        boolean valid = Sign.verify(file, key);
        assertTrue(valid, "Signature should be valid immediately after signing");
    }

    @Test
    void verify_returnsFalse_afterTamper() throws Exception {
        Path file = tmp.resolve("test.json");
        Path key  = tmp.resolve("test.key");
        Files.writeString(file, "{\"data\":\"hello\"}");
        Sign.generateKey(key);
        Sign.sign(file, key);
        Files.writeString(file, "{\"data\":\"TAMPERED\"}");
        boolean valid = Sign.verify(file, key);
        assertFalse(valid, "Signature should be invalid after file modification");
    }

    @Test
    void sign_producesSigFile() throws Exception {
        Path file = tmp.resolve("report.json");
        Path key  = tmp.resolve("test.key");
        Files.writeString(file, "{}");
        Sign.generateKey(key);
        Sign.sign(file, key);
        Path sig = tmp.resolve("report.json.sig");
        assertTrue(Files.exists(sig), ".sig file should be created");
    }
}
