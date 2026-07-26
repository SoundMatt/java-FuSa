package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.verify.Verify;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class VerifyTest {

    @TempDir Path tmp;

    // ── REQ-VERIFY001 ─────────────────────────────────────────────────────────

    @Test
    //fusa:test REQ-VERIFY001
    void verify_saveEvidence_writesFileWithCorrectSchemaVersionAndKind() throws Exception {
        Config cfg = Config.defaultConfig("verify-test");
        Verify.saveEvidence(tmp, cfg, 0, "test notes");
        Path evidence = tmp.resolve(Verify.EVIDENCE_FILE);
        assertTrue(Files.exists(evidence), ".fusa-evidence.json should be written");
        String content = Files.readString(evidence);
        assertTrue(content.contains("\"schemaVersion\""),
                "evidence file must contain schemaVersion field");
        assertTrue(content.contains("\"kind\""),
                "evidence file must contain kind field");
        assertTrue(content.contains("\"verify-report\""),
                "kind value must be verify-report");
    }

    @Test
    //fusa:test REQ-VERIFY001
    void verify_ruleEvidencePresent_emitsWarningWhenFileAbsent() throws Exception {
        Config cfg = Config.defaultConfig("verify-test");
        Config.save(tmp, cfg);
        // Ensure Verify is loaded so VERIFY001 rule is registered in Engine.DEFAULT
        Verify.activate();
        // Use runFilter to isolate only the VERIFY001 rule
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("VERIFY001"));
        List<FuSa.Finding> findings = result.findings();
        assertFalse(findings.isEmpty(),
                "RuleEvidencePresent should emit a finding when .fusa-evidence.json is absent");
        assertEquals(FuSa.Severity.WARNING, findings.get(0).severity(),
                "finding severity should be WARNING");
        assertEquals("VERIFY001", findings.get(0).ruleId(),
                "finding ruleId should be VERIFY001");
    }

    @Test
    //fusa:test REQ-VERIFY001
    void verify_ruleEvidencePresent_returnsEmptyWhenFilePresent() throws Exception {
        Config cfg = Config.defaultConfig("verify-test");
        Config.save(tmp, cfg);
        Verify.saveEvidence(tmp, cfg, 0, "passing tests");
        Verify.activate();
        Engine.Result result = Engine.DEFAULT.runFilter(tmp, cfg,
                r -> r.id().equals("VERIFY001"));
        List<FuSa.Finding> findings = result.findings();
        assertTrue(findings.isEmpty(),
                "RuleEvidencePresent should return empty findings when .fusa-evidence.json exists");
    }
}
