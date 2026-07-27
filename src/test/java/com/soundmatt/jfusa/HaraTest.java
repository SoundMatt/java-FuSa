package com.soundmatt.jfusa;

import com.soundmatt.jfusa.hara.Hara;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class HaraTest {

    @TempDir Path tmp;

    // ── deriveAsil() — ISO 26262-3 Table 4 ────────────────────────────────────

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_severityZero_isAlwaysQM() {
        assertEquals("QM", Hara.deriveAsil(0, 1, 1));
        assertEquals("QM", Hara.deriveAsil(0, 4, 3));
    }

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_severityTwo_lowExposure_isQM() {
        assertEquals("QM", Hara.deriveAsil(2, 1, 3));
    }

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_severityTwo_highExposureHighControllability_isB() {
        // s=2, e=3, c=3 -> c<=1? no; c==2? no -> "B"
        assertEquals("B", Hara.deriveAsil(2, 3, 3));
    }

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_matchesDefaultHazardH001() {
        // H-001 in Hara.defaults(): S3, E3, C2 -> asil "ASIL-C" (bare letter "C" from deriveAsil)
        assertEquals("C", Hara.deriveAsil(3, 3, 2));
    }

    @Test
    //fusa:test REQ-HARA001
    void deriveAsil_severityThree_highestExposureAndControllability_isD() {
        // s=3, e>=4, c==2 -> "D"
        assertEquals("D", Hara.deriveAsil(3, 4, 2));
    }

    // ── init() / show() / defaults() ──────────────────────────────────────────

    //fusa:test REQ-HARA002
    @Test
    void init_writesHaraFile() throws Exception {
        Hara.init(tmp, "hara-test");
        assertTrue(Files.exists(tmp.resolve(Hara.HARA_FILE)));
    }

    //fusa:test REQ-HARA002
    @Test
    void init_doesNotOverwriteExisting() throws Exception {
        Hara.init(tmp, "hara-test");
        String before = Files.readString(tmp.resolve(Hara.HARA_FILE));
        Hara.init(tmp, "different-name");
        String after = Files.readString(tmp.resolve(Hara.HARA_FILE));
        assertEquals(before, after, "init() must not overwrite an existing .fusa-hara.json");
    }

    //fusa:test REQ-HARA002
    @Test
    void show_withoutFile_returnsPlaceholderMessage() throws Exception {
        String out = Hara.show(tmp);
        assertTrue(out.contains("No .fusa-hara.json found"));
    }

    //fusa:test REQ-HARA002
    @Test
    void show_afterInit_listsHazards() throws Exception {
        Hara.init(tmp, "hara-test");
        String out = Hara.show(tmp);
        assertTrue(out.contains("H-001"));
        assertTrue(out.contains("HARA"));
    }

    //fusa:test REQ-HARA002
    @Test
    void defaults_returnsThreeHazards() {
        assertEquals(3, Hara.defaults("proj").size());
    }
}
