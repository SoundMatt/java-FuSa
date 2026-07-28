package com.soundmatt.jfusa;

import com.soundmatt.jfusa.sas.Sas;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class SasTest {

    @TempDir Path tmp;

    @Test
    //fusa:test REQ-SAS001
    void build_countsPresentLifecycleItems() throws Exception {
        Files.writeString(tmp.resolve(".fusa.json"), "{}");
        Sas.SasReport report = Sas.build(tmp);
        assertTrue(report.summary().present() >= 1);
        assertEquals(report.checklist().size(), report.summary().total());
    }

    @Test
    //fusa:test REQ-SAS002
    void writeJson_producesChecklistAndSummary() throws Exception {
        Sas.SasReport report = Sas.build(tmp);
        Sas.writeJson(tmp, report, "");
        String json = Files.readString(tmp.resolve(Sas.SAS_JSON));
        assertTrue(json.contains("\"checklist\""));
        assertTrue(json.contains("\"summary\""));
        assertTrue(json.contains("\"kind\": \"sas\""));
    }

    @Test
    //fusa:test REQ-SAS002
    void writeJson_carriesForwardExistingAttestation() throws Exception {
        Files.writeString(tmp.resolve(Sas.SAS_JSON), """
                {"attestation": {"status":"reviewed","implementationAuthor":"auto",
                 "independentReviewer":"Jane Doe","reviewedAt":"2026-07-28T00:00:00Z",
                 "contentHash":"sha256:x"}}
                """);
        Sas.SasReport report = Sas.build(tmp);
        assertNotNull(report.attestation());
        assertEquals("Jane Doe", report.attestation().independentReviewer());
    }

    @Test
    //fusa:test REQ-SAS003
    void writeMarkdown_producesSasMd() throws Exception {
        Sas.SasReport report = Sas.build(tmp);
        Sas.writeMarkdown(tmp, report);
        assertTrue(Files.exists(tmp.resolve(Sas.SAS_MD)));
    }

    @Test
    //fusa:test REQ-SAS005
    void qualityBarFields_oneEntryPerChecklistItem() throws Exception {
        Sas.SasReport report = Sas.build(tmp);
        assertEquals(report.checklist().size(), Sas.qualityBarFields(report.checklist()).size());
    }

    @Test
    //fusa:test REQ-SAS001
    void generate_writesMarkdownOnly() throws Exception {
        Sas.generate(tmp);
        assertTrue(Files.exists(tmp.resolve(Sas.SAS_MD)));
    }
}
