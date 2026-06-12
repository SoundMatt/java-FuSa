package com.soundmatt.jfusa.sign;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;

/** Sign or verify a file with HMAC-SHA256. */
public final class Sign {

    private Sign() {}

    /** Generate a new HMAC-SHA256 key and write to keyFile (hex-encoded). */
    public static void generateKey(Path keyFile) throws IOException {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        Files.writeString(keyFile, HexFormat.of().formatHex(key) + "\n");
        System.out.println("Key written to " + keyFile);
    }

    /** Sign artifact; writes <artifact>.sig containing the HMAC-SHA256 hex. */
    public static void sign(Path artifact, Path keyFile) throws IOException {
        byte[] key   = HexFormat.of().parseHex(Files.readString(keyFile).strip());
        byte[] data  = Files.readAllBytes(artifact);
        String hmac  = hmacSha256(key, data);
        Path sigFile = artifact.resolveSibling(artifact.getFileName() + ".sig");
        Files.writeString(sigFile, hmac + "\n");
        System.out.println("Signed " + artifact + " → " + sigFile);
    }

    /** Verify artifact against <artifact>.sig. Returns true if valid. */
    public static boolean verify(Path artifact, Path keyFile) throws IOException {
        Path sigFile = artifact.resolveSibling(artifact.getFileName() + ".sig");
        if (!Files.exists(sigFile)) { System.err.println("No .sig file found for " + artifact); return false; }
        byte[] key      = HexFormat.of().parseHex(Files.readString(keyFile).strip());
        byte[] data     = Files.readAllBytes(artifact);
        String expected = Files.readString(sigFile).strip();
        String actual   = hmacSha256(key, data);
        boolean ok = expected.equalsIgnoreCase(actual);
        System.out.println(ok ? "Signature VALID" : "Signature INVALID");
        return ok;
    }

    static String hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(data));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }
}
