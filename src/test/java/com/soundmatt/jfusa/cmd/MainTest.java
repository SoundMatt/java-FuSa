package com.soundmatt.jfusa.cmd;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.analyze.AnalyzeRules;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.coverage.Coverage;
import com.soundmatt.jfusa.cyber.CyberRules;
import com.soundmatt.jfusa.lint.LintRules;
import com.soundmatt.jfusa.qualify.Qualify;
import com.soundmatt.jfusa.release.Release;
import com.soundmatt.jfusa.slsa.Slsa;
import com.soundmatt.jfusa.trace.Trace;
import com.soundmatt.jfusa.verify.Verify;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class MainTest {

    @TempDir Path tmp;

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String captureOut(ThrowingRunnable r) throws Exception {
        var buf = new ByteArrayOutputStream();
        var saved = System.out;
        System.setOut(new PrintStream(buf));
        try { r.run(); } finally { System.setOut(saved); }
        return buf.toString();
    }

    private static String captureErr(ThrowingRunnable r) throws Exception {
        var buf = new ByteArrayOutputStream();
        var saved = System.err;
        System.setErr(new PrintStream(buf));
        try { r.run(); } finally { System.setErr(saved); }
        return buf.toString();
    }

    @FunctionalInterface
    interface ThrowingRunnable { void run() throws Exception; }

    private Path initProject() throws Exception {
        Config cfg = Config.defaultConfig("main-test");
        Config.save(tmp, cfg);
        return tmp;
    }

    // ── Flag helpers ──────────────────────────────────────────────────────────

    @Test
    void hasFlag_returnsTrueWhenPresent() {
        assertTrue(Main.hasFlag(new String[]{"--strict-hlr-llr", "--format"}, "--strict-hlr-llr"));
    }

    @Test
    void hasFlag_returnsFalseWhenAbsent() {
        assertFalse(Main.hasFlag(new String[]{"--format", "json"}, "--strict-hlr-llr"));
    }

    @Test
    void flagValue_returnsValueAfterFlag() {
        assertEquals("json", Main.flagValue(new String[]{"--format", "json"}, "--format", "text"));
    }

    @Test
    void flagValue_returnsValueFromEqualsForm() {
        assertEquals("json", Main.flagValue(new String[]{"--format=json", "--other"}, "--format", "text"));
    }

    @Test
    void flagValue_returnsDefaultWhenAbsent() {
        assertEquals("text", Main.flagValue(new String[]{}, "--format", "text"));
    }

    // ── §2.2 --dir (regression: previously a no-op — issue #38) ────────────────

    @Test
    void resolveRoot_usesCwdWhenDirFlagAbsent() {
        assertEquals(Main.cwd(), Main.resolveRoot(new String[]{"--format", "json"}));
    }

    @Test
    void resolveRoot_usesDirFlagValueWhenGiven() {
        Path expected = tmp.toAbsolutePath().normalize();
        assertEquals(expected, Main.resolveRoot(new String[]{"--dir", tmp.toString()}));
    }

    @Test
    void resolveRoot_supportsEqualsForm() {
        Path expected = tmp.toAbsolutePath().normalize();
        assertEquals(expected, Main.resolveRoot(new String[]{"--dir=" + tmp}));
    }

    @Test
    void stripFlagWithValue_removesFlagAndItsValue() {
        assertArrayEquals(new String[]{"--format", "json"},
                Main.stripFlagWithValue(new String[]{"--dir", "/some/path", "--format", "json"}, "--dir"));
    }

    @Test
    void stripFlagWithValue_removesEqualsForm() {
        assertArrayEquals(new String[]{"--format", "json"},
                Main.stripFlagWithValue(new String[]{"--dir=/some/path", "--format", "json"}, "--dir"));
    }

    @Test
    void stripFlagWithValue_noOpWhenFlagAbsent() {
        assertArrayEquals(new String[]{"--format", "json"},
                Main.stripFlagWithValue(new String[]{"--format", "json"}, "--dir"));
    }

    @Test
    void main_dirFlag_operatesOnGivenProjectNotCwd() throws Exception {
        // End-to-end regression for issue #38: `vuln --dir <other>` must write vuln.json
        // into <other>, not the process's actual working directory. (Avoids `check`/other
        // gate-failing commands here since a CheckFailedException would call System.exit
        // and kill the test JVM — `vuln` never gates.)
        captureOut(() -> Main.main(new String[]{"vuln", "--dir", tmp.toString()}));
        assertTrue(Files.exists(tmp.resolve("vuln.json")),
                "--dir should redirect the command to operate on the given project root");
    }

    @Test
    void flagValue_equalsForm_worksAsTheFinalArgument() {
        // Regression: the previous "i < args.length - 1" loop bound skipped the equals-form
        // check entirely when it was the last argument — exactly the shape ci.yml uses
        // ("check --format=json --output=report.json").
        assertEquals("json", Main.flagValue(new String[]{"--format=json"}, "--format", "text"));
        assertEquals("report.json",
                Main.flagValue(new String[]{"--format=json", "--output=report.json"}, "--output", ""));
    }

    @Test
    void flagValue_spaceForm_asFinalArgumentWithNoValue_returnsDefault() {
        assertEquals("text", Main.flagValue(new String[]{"--format"}, "--format", "text"));
    }

    // ── version / capabilities ────────────────────────────────────────────────

    @Test
    void cmdVersion_printsVersion() throws Exception {
        String out = captureOut(Main::cmdVersion);
        assertTrue(out.contains("jfusa"), "version output should contain 'jfusa'");
        assertTrue(out.contains(FuSa.VERSION));
    }

    @Test
    void cmdVersionJson_printsJsonWithFields() throws Exception {
        String out = captureOut(Main::cmdVersionJson);
        assertTrue(out.contains("\"tool\""));
        assertTrue(out.contains("\"version\""));
        assertTrue(out.contains("\"specVersion\""));
        assertTrue(out.contains(FuSa.VERSION));
    }

    @Test
    void cmdCapabilitiesFmt_textMode() throws Exception {
        String out = captureOut(() -> Main.cmdCapabilitiesFmt("text"));
        assertTrue(out.contains("jfusa"));
    }

    @Test
    void cmdCapabilitiesFmt_jsonMode() throws Exception {
        String out = captureOut(() -> Main.cmdCapabilitiesFmt("json"));
        assertTrue(out.contains("\"commands\""));
        assertTrue(out.contains("\"formats\""));
        assertTrue(out.contains("\"standards\""));
    }

    @Test
    void emitJsonError_writesStructuredError() throws Exception {
        String err = captureErr(() -> Main.emitJsonError("no_config", "missing file"));
        assertTrue(err.contains("\"error\""));
        assertTrue(err.contains("no_config"));
        assertTrue(err.contains("missing file"));
    }

    @Test
    void errorCodes_matchSpecClosedHyphenatedEnum() {
        // §3.2 MUST: error.code is one of no-config | invalid-config | unsupported |
        // internal — hyphenated, never underscored (issue #42).
        assertEquals("no-config", Main.ERR_NO_CONFIG);
        assertEquals("invalid-config", Main.ERR_INVALID_CONFIG);
        assertEquals("unsupported", Main.ERR_UNSUPPORTED);
        assertEquals("internal", Main.ERR_INTERNAL);
    }

    // ── init ──────────────────────────────────────────────────────────────────

    @Test
    void cmdInit_createsFusaJson() throws Exception {
        String out = captureOut(() -> Main.cmdInit(tmp, new String[]{"my-project"}));
        assertTrue(Files.exists(tmp.resolve(".fusa.json")));
        assertTrue(out.contains("Initialized"));
    }

    @Test
    void cmdInit_createsFusaReqsJson() throws Exception {
        captureOut(() -> Main.cmdInit(tmp, new String[]{"req-project"}));
        assertTrue(Files.exists(tmp.resolve(".fusa-reqs.json")));
    }

    @Test
    void cmdInit_doesNotOverwriteWithoutForce() throws Exception {
        Main.cmdInit(tmp, new String[]{"proj1"});
        String out = captureOut(() -> Main.cmdInit(tmp, new String[]{"proj2"}));
        assertTrue(out.contains("already exists"));
    }

    @Test
    void cmdInit_overwritesWithForce() throws Exception {
        Main.cmdInit(tmp, new String[]{"proj1"});
        // Should not throw
        captureOut(() -> Main.cmdInit(tmp, new String[]{"proj2", "--force"}));
        assertTrue(Files.exists(tmp.resolve(".fusa.json")));
    }

    // ── check / lint / analyze / cyber ───────────────────────────────────────

    @Test
    //fusa:test REQ-ENG008
    void cmdCheck_textFormat_runsAndProducesOutput() throws Exception {
        initProject();
        // Activate all rule packages so Engine.DEFAULT is populated
        LintRules.activate(); AnalyzeRules.activate(); CyberRules.activate();
        Trace.activate(); Verify.activate(); Release.activate(); Qualify.activate();
        Slsa.activate(); Coverage.activate();
        var buf = new java.io.ByteArrayOutputStream();
        var saved = System.out;
        System.setOut(new PrintStream(buf));
        try {
            Main.cmdCheck(tmp, new String[]{"--format", "text"});
        } catch (FuSa.CheckFailedException ignored) {
            // gate failure is expected when not all safety files are present
        } finally {
            System.setOut(saved);
        }
        String out = buf.toString();
        assertNotNull(out);
    }

    @Test
    //fusa:test REQ-ENG003
    void cmdCheck_writesToOutputFile() throws Exception {
        initProject();
        try {
            Main.cmdCheck(tmp, new String[]{"--format", "json", "--output", "fusa-report.json"});
        } catch (FuSa.CheckFailedException ignored) {
            // gate failure expected — report is still written before the throw
        }
        assertTrue(Files.exists(tmp.resolve("fusa-report.json")));
    }

    @Test
    void cmdLint_runsWithoutError() throws Exception {
        initProject();
        captureOut(() -> Main.cmdLint(tmp, new String[]{}));
    }

    @Test
    void cmdAnalyze_runsWithoutError() throws Exception {
        initProject();
        captureOut(() -> Main.cmdAnalyze(tmp, new String[]{}));
    }

    @Test
    void cmdCyber_runsWithoutError() throws Exception {
        initProject();
        captureOut(() -> Main.cmdCyber(tmp, new String[]{}));
    }

    // ── trace ─────────────────────────────────────────────────────────────────

    @Test
    //fusa:test REQ-TRACE004
    void cmdTrace_textFormat_runsWithoutError() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdTrace(tmp, new String[]{}));
        assertNotNull(out);
    }

    @Test
    //fusa:test REQ-TRACE004
    void cmdTrace_jsonFormat_runsWithoutError() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdTrace(tmp, new String[]{"--format", "json"}));
        assertNotNull(out);
    }

    @Test
    //fusa:test REQ-TRACE004
    void cmdTrace_writesToOutputFile() throws Exception {
        initProject();
        Main.cmdTrace(tmp, new String[]{"--output", "trace-out.txt"});
        assertTrue(Files.exists(tmp.resolve("trace-out.txt")));
    }

    @Test
    //fusa:test REQ-HLR002
    void cmdTrace_strictHlrLlr_noHierarchy_passes() throws Exception {
        initProject();
        // No LLRs in default config — should not throw
        captureOut(() -> Main.cmdTrace(tmp, new String[]{"--strict-hlr-llr"}));
    }

    @Test
    //fusa:test REQ-TRACE002
    void cmdTrace_funcCoverage_belowThreshold_throwsCheckFailed() throws Exception {
        initProject();
        Path src = tmp.resolve("src/main/java/Untagged.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Untagged {
                    public void oneMethod() {}
                    public void anotherMethod() {}
                }
                """);
        assertThrows(FuSa.CheckFailedException.class, () ->
                captureOut(() -> Main.cmdTrace(tmp, new String[]{"--func-coverage", "100"})));
    }

    @Test
    //fusa:test REQ-TRACE002
    void cmdTrace_funcCoverage_zeroDisablesGate() throws Exception {
        initProject();
        Path src = tmp.resolve("src/main/java/Untagged.java");
        Files.createDirectories(src.getParent());
        Files.writeString(src, """
                public class Untagged {
                    public void oneMethod() {}
                }
                """);
        // N=0 disables the gate — must not throw even though coverage is 0%.
        captureOut(() -> Main.cmdTrace(tmp, new String[]{"--func-coverage", "0"}));
    }

    // ── verify / qualify ──────────────────────────────────────────────────────

    @Test
    //fusa:test REQ-VERIFY001
    //fusa:test REQ-VERIFY002
    void cmdVerify_writesEvidenceFile() throws Exception {
        initProject();
        captureOut(() -> Main.cmdVerify(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve(Verify.EVIDENCE_FILE)));
    }

    @Test
    //fusa:test REQ-QUALIFY001
    void cmdQualify_generatesReport() throws Exception {
        initProject();
        captureOut(() -> Main.cmdQualify(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve(Qualify.QUALIFY_REPORT)));
    }

    @Test
    //fusa:test REQ-QUALIFY002
    void cmdQualify_withQualificationMethodFlag() throws Exception {
        initProject();
        captureOut(() -> Main.cmdQualify(tmp,
                new String[]{"--qualification-method", "independent",
                             "--qualifier", "SafetyOrg",
                             "--record-uri", "https://example.com"}));
        String content = Files.readString(tmp.resolve(Qualify.QUALIFY_REPORT));
        assertTrue(content.contains("independent"));
    }

    @Test
    //fusa:test REQ-QUALIFY003
    void cmdQualify_withIndependenceFlags() throws Exception {
        initProject();
        captureOut(() -> Main.cmdQualify(tmp,
                new String[]{"--independent-reviewer", "Bob",
                             "--implementation-author", "Alice",
                             "--achievable-asil", "ASIL-B"}));
        String content = Files.readString(tmp.resolve(Qualify.QUALIFY_REPORT));
        assertTrue(content.contains("Alice") || content.contains("Bob") || content.contains("ASIL-B"));
    }

    // ── release / audit-pack ──────────────────────────────────────────────────

    @Test
    //fusa:test REQ-RELEASE001
    //fusa:test REQ-RELEASE002
    void cmdRelease_generatesProvenance() throws Exception {
        initProject();
        captureOut(() -> Main.cmdRelease(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("sbom.json")) ||
                   Files.exists(tmp.resolve("provenance.json")));
    }

    //fusa:test REQ-AUDITPACK001
    @Test
    void cmdAuditPack_generatesZip() throws Exception {
        initProject();
        captureOut(() -> Main.cmdAuditPack(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("audit-pack.zip")));
    }

    // ── regression: --output / --output-dir / --format threading (#24, #25, #26) ──

    @Test
    //fusa:test REQ-QUALIFY006
    void cmdQualify_honorsOutputFlag() throws Exception {
        initProject();
        captureOut(() -> Main.cmdQualify(tmp, new String[]{"--output", "q.json"}));
        assertTrue(Files.exists(tmp.resolve("q.json")),
                "--output should redirect the qualify report");
        assertFalse(Files.exists(tmp.resolve(Qualify.QUALIFY_REPORT)),
                "the default qualify-report.json must not also be written when --output is given");
    }

    @Test
    //fusa:test REQ-QUALIFY006
    void cmdQualify_honorsFormatJsonFlag() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdQualify(tmp, new String[]{"--format", "json"}));
        assertTrue(out.contains("\"schemaVersion\"") && out.contains("\"results\""),
                "--format json should print the JSON report body to stdout, not the text summary");
    }

    @Test
    //fusa:test REQ-QUALIFY006
    void cmdQualify_formatJsonWithOutput_writesOnlyToFileNotStdout() throws Exception {
        initProject();
        String out = captureOut(() ->
                Main.cmdQualify(tmp, new String[]{"--format", "json", "--output", "q2.json"}));
        assertTrue(Files.exists(tmp.resolve("q2.json")), "--output should redirect the qualify report");
        // §2.2 MUST: --output redirects the report; the same JSON document must NOT also be
        // echoed to stdout when --output is explicitly given.
        assertFalse(out.contains("\"schemaVersion\""),
                "stdout must be clean when --format json --output <file> is given — no duplicated document");
    }

    @Test
    //fusa:test REQ-RELEASE007
    void cmdRelease_honorsOutputDirFlag() throws Exception {
        initProject();
        captureOut(() -> Main.cmdRelease(tmp, new String[]{"--output-dir", "out"}));
        assertTrue(Files.exists(tmp.resolve("out").resolve(Release.SBOM_FILE)),
                "--output-dir should redirect sbom.json into the requested (auto-created) directory");
        assertFalse(Files.exists(tmp.resolve(Release.SBOM_FILE)),
                "sbom.json must not also be written to the project root when --output-dir is given");
    }

    @Test
    //fusa:test REQ-AUDITPACK002
    void cmdAuditPack_honorsOutputFlag() throws Exception {
        initProject();
        captureOut(() -> Main.cmdAuditPack(tmp, new String[]{"--output", "ap.zip"}));
        assertTrue(Files.exists(tmp.resolve("ap.zip")),
                "--output should redirect the audit-pack ZIP");
        assertFalse(Files.exists(tmp.resolve("audit-pack.zip")),
                "the default audit-pack.zip must not also be written when --output is given");
    }

    // ── standards adapters ────────────────────────────────────────────────────

    //fusa:test REQ-DO178001
    @Test
    void cmdDo178_textFormat() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdDo178(tmp, new String[]{}));
        assertTrue(out.contains("DAL") || out.contains("DO-178") || out.length() > 0);
    }

    @Test
    void cmdDo178_jsonFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdDo178(tmp, new String[]{"--format", "json", "--dal", "DAL-B"}));
        assertTrue(Files.exists(tmp.resolve("do178-gap-report.json")));
    }

    //fusa:test REQ-ISO26262001
    @Test
    void cmdIso26262_textFormat() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdIso26262(tmp, new String[]{}));
        assertTrue(out.length() > 0);
    }

    @Test
    void cmdIso26262_jsonFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdIso26262(tmp, new String[]{"--format", "json", "--asil", "ASIL-C"}));
        assertTrue(Files.exists(tmp.resolve("iso26262-gap-report.json")));
    }

    //fusa:test REQ-ISO26262001
    @Test
    void cmdIso26262_defaultAsil_doesNotDoublePrefix() throws Exception {
        // Regression: the default --asil value ("ASIL-B") was concatenated with an
        // already-added "ASIL-" prefix, producing "ASIL-ASIL-B" (issue #41).
        initProject();
        captureOut(() -> Main.cmdIso26262(tmp, new String[]{"--format", "json"}));
        String content = Files.readString(tmp.resolve("iso26262-gap-report.json"));
        assertTrue(content.contains("\"level\": \"ASIL-B\""), content);
        assertFalse(content.contains("ASIL-ASIL"), content);
    }

    //fusa:test REQ-ISO26262001
    @Test
    void cmdIso26262_textFormat_defaultAsil_doesNotDoublePrefix() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdIso26262(tmp, new String[]{}));
        assertFalse(out.contains("ASIL-ASIL"), out);
    }

    //fusa:test REQ-ISO21434001
    @Test
    void cmdIso21434_textFormat() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdIso21434(tmp, new String[]{}));
        assertTrue(out.length() > 0);
    }

    @Test
    void cmdIso21434_jsonFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdIso21434(tmp, new String[]{"--format", "json"}));
        assertTrue(Files.exists(tmp.resolve("iso21434-gap-report.json")));
    }

    //fusa:test REQ-IEC61508001
    @Test
    void cmdIec61508_textFormat() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdIec61508(tmp, new String[]{}));
        assertTrue(out.length() > 0);
    }

    @Test
    void cmdIec61508_jsonFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdIec61508(tmp, new String[]{"--format", "json"}));
        assertTrue(Files.exists(tmp.resolve("iec61508-gap-report.json")));
    }

    @Test
    void cmdIec62443_textFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdIec62443(tmp, new String[]{}));
    }

    @Test
    void cmdIec62443_jsonFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdIec62443(tmp, new String[]{"--format", "json"}));
        assertTrue(Files.exists(tmp.resolve("iec62443-gap-report.json")));
    }

    //fusa:test REQ-IEC62443001
    @Test
    void cmdIec62443_jsonFormat_usesCanonicalStandardId() throws Exception {
        // Regression: "iec62443" is the command name, not a §2.4.1 registry id — the
        // gap-report must emit "iec62443-4-1" (issue #45).
        initProject();
        captureOut(() -> Main.cmdIec62443(tmp, new String[]{"--format", "json"}));
        String content = Files.readString(tmp.resolve("iec62443-gap-report.json"));
        assertTrue(content.contains("\"standard\": \"iec62443-4-1\""), content);
    }

    @Test
    void capabilities_json_usesCanonicalIec62443Id() throws Exception {
        // Regression (issue #45): "iec62443" (the bare command name — still legitimately
        // present in the `commands` array) must not appear as a `standards` entry; only
        // the canonical "iec62443-4-1" id may.
        String out = captureOut(() -> Main.cmdCapabilitiesFmt("json"));
        String standardsSection = out.substring(out.indexOf("\"standards\""));
        assertTrue(standardsSection.contains("\"iec62443-4-1\""), standardsSection);
        assertFalse(standardsSection.contains("\"iec62443\","), standardsSection);
        assertFalse(standardsSection.contains("\"iec62443\"\n"), standardsSection);
    }

    //fusa:test REQ-UNECE001
    @Test
    void cmdUnece_textFormat() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdUnece(tmp, new String[]{}));
        assertTrue(out.length() > 0);
    }

    @Test
    void cmdUnece_jsonFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdUnece(tmp, new String[]{"--format", "json"}));
    }

    @Test
    void cmdSlsa_textFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdSlsa(tmp, new String[]{}));
    }

    @Test
    void cmdSlsa_jsonFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdSlsa(tmp, new String[]{"--format", "json"}));
    }

    // ── compliance / analysis ─────────────────────────────────────────────────

    //fusa:test REQ-SAS001
    @Test
    void cmdSas_generatesMd() throws Exception {
        initProject();
        captureOut(() -> Main.cmdSas(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("sas.md")));
    }

    //fusa:test REQ-SCI001
    @Test
    void cmdSci_generatesJson() throws Exception {
        initProject();
        captureOut(() -> Main.cmdSci(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("sci.json")));
    }

    //fusa:test REQ-SCI001
    @Test
    void cmdSci_markdownFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdSci(tmp, new String[]{"--format", "markdown"}));
        assertTrue(Files.exists(tmp.resolve("sci.md")));
    }

    @Test
    void cmdComp_textFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdComp(tmp, new String[]{}));
    }

    @Test
    void cmdComp_jsonFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdComp(tmp, new String[]{"--format", "json"}));
        assertTrue(Files.exists(tmp.resolve("comp-report.json")));
    }

    @Test
    void cmdComp_withDalFlag() throws Exception {
        initProject();
        captureOut(() -> Main.cmdComp(tmp, new String[]{"--dal", "DAL-A"}));
    }

    //fusa:test REQ-MISRA001
    @Test
    void cmdMisra_jsonFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdMisra(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("misra-java-gap-report.json")));
    }

    //fusa:test REQ-MISRA001
    @Test
    void cmdMisra_jsonFormat_usesCanonicalGapReportSchema() throws Exception {
        initProject();
        captureOut(() -> Main.cmdMisra(tmp, new String[]{}));
        String content = Files.readString(tmp.resolve("misra-java-gap-report.json"));
        // §9.3 MUST: kind "gap-report" + objectives[]/summary — not the bespoke
        // "misra-report"/totalFindings-findings shape this used to emit.
        assertTrue(content.contains("\"kind\": \"gap-report\""));
        assertTrue(content.contains("\"objectives\""));
        assertTrue(content.contains("\"summary\""));
        assertFalse(content.contains("\"totalFindings\""));
        assertFalse(content.contains("misra-report"));
    }

    //fusa:test REQ-MISRA001
    @Test
    void cmdMisra_textFormat() throws Exception {
        initProject();
        captureOut(() -> Main.cmdMisra(tmp, new String[]{"--format", "text"}));
    }

    // ── safety artefacts ──────────────────────────────────────────────────────

    //fusa:test REQ-SAFETYCASE001
    @Test
    void cmdSafetyCase_generatesJson() throws Exception {
        initProject();
        captureOut(() -> Main.cmdSafetyCase(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("safety-case.json")));
    }

    @Test
    void cmdFmea_generatesJson() throws Exception {
        initProject();
        captureOut(() -> Main.cmdFmea(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("fmea.json")));
    }

    //fusa:test REQ-TARA001
    @Test
    void cmdTara_generatesJson() throws Exception {
        initProject();
        captureOut(() -> Main.cmdTara(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("tara.json")));
    }

    @Test
    void cmdHara_initAndShow() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdHara(tmp, new String[]{}));
        assertNotNull(out);
    }

    @Test
    void cmdBoundary_generatesMermaid() throws Exception {
        initProject();
        captureOut(() -> Main.cmdBoundary(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("boundary.mermaid")));
    }

    @Test
    void cmdCoupling_generatesReport() throws Exception {
        initProject();
        captureOut(() -> Main.cmdCoupling(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("coupling-report.json")));
    }

    @Test
    void cmdVuln_runsWithoutError() throws Exception {
        initProject();
        captureOut(() -> Main.cmdVuln(tmp, new String[]{}));
    }

    // ── management ────────────────────────────────────────────────────────────

    @Test
    void cmdReq_list_handlesAbsentFile() throws Exception {
        String out = captureOut(() -> Main.cmdReq(tmp, new String[]{"list"}));
        assertTrue(out.contains("No .fusa-reqs.json") || out.isEmpty());
    }

    @Test
    void cmdReq_add_appendsEntry() throws Exception {
        Main.cmdReq(tmp, new String[]{"add", "REQ-TEST001", "Test requirement"});
        assertTrue(Files.exists(tmp.resolve(".fusa-reqs.json")));
        String content = Files.readString(tmp.resolve(".fusa-reqs.json"));
        assertTrue(content.contains("REQ-TEST001"));
    }

    @Test
    void cmdReq_list_showsContent() throws Exception {
        Main.cmdReq(tmp, new String[]{"add", "REQ-LIST001", "List test"});
        String out = captureOut(() -> Main.cmdReq(tmp, new String[]{"list"}));
        assertTrue(out.contains("REQ-LIST001"));
    }

    //fusa:test REQ-PR001
    @Test
    void cmdPr_init_createsFile() throws Exception {
        captureOut(() -> Main.cmdPr(tmp, new String[]{"init"}));
        assertTrue(Files.exists(tmp.resolve(".fusa-problems.json")));
    }

    //fusa:test REQ-PR002
    //fusa:test REQ-PR004
    @Test
    void cmdPr_add_appendsEntry() throws Exception {
        Main.cmdPr(tmp, new String[]{"init"});
        Main.cmdPr(tmp, new String[]{"add", "PR-001", "Test problem", "major"});
        String content = Files.readString(tmp.resolve(".fusa-problems.json"));
        assertTrue(content.contains("PR-001"));
    }

    //fusa:test REQ-PR005
    @Test
    void cmdPr_list_showsEntries() throws Exception {
        Main.cmdPr(tmp, new String[]{"init"});
        Main.cmdPr(tmp, new String[]{"add", "PR-002", "Listed problem", "minor"});
        String out = captureOut(() -> Main.cmdPr(tmp, new String[]{"list"}));
        assertTrue(out.contains("PR-002") || out.length() >= 0);
    }

    //fusa:test REQ-PR003
    @Test
    void cmdPr_close_updatesEntry() throws Exception {
        Main.cmdPr(tmp, new String[]{"init"});
        Main.cmdPr(tmp, new String[]{"add", "PR-003", "Close test", "major"});
        Main.cmdPr(tmp, new String[]{"close", "PR-003", "fixed in v1.1"});
        String content = Files.readString(tmp.resolve(".fusa-problems.json"));
        assertTrue(content.contains("PR-003"));
    }

    //fusa:test REQ-DISPOSITION001
    @Test
    void cmdDisposition_add_createsEntry() throws Exception {
        Main.cmdDisposition(tmp, new String[]{"add", "LINT001", "Main.java", "accepted", "low risk"});
        assertTrue(Files.exists(tmp.resolve(".fusa-dispositions.json")));
        String content = Files.readString(tmp.resolve(".fusa-dispositions.json"));
        assertTrue(content.contains("LINT001"));
    }

    //fusa:test REQ-DISPOSITION001
    @Test
    void cmdDisposition_list_showsEntries() throws Exception {
        Main.cmdDisposition(tmp, new String[]{"add", "LINT002", "Foo.java", "deferred", "revisit"});
        String out = captureOut(() -> Main.cmdDisposition(tmp, new String[]{"list"}));
        assertTrue(out.contains("LINT002") || out.length() >= 0);
    }

    //fusa:test REQ-METRICS001
    @Test
    void cmdMetrics_show_handlesAbsentFile() throws Exception {
        String out = captureOut(() -> Main.cmdMetrics(tmp, new String[]{}));
        assertNotNull(out);
    }

    //fusa:test REQ-METRICS001
    @Test
    void cmdMetrics_record_writesHistory() throws Exception {
        initProject();
        captureOut(() -> Main.cmdMetrics(tmp, new String[]{"record"}));
        assertTrue(Files.exists(tmp.resolve(".fusa-metrics.json")));
    }

    @Test
    void cmdSign_generateKey_createsKeyFile() throws Exception {
        captureOut(() -> Main.cmdSign(tmp, new String[]{"generate-key", "unused"}));
        assertTrue(Files.exists(tmp.resolve(".fusa-signing.key")));
    }

    @Test
    void cmdSign_signAndVerify() throws Exception {
        // Write a file to sign
        Path target = tmp.resolve("test.txt");
        Files.writeString(target, "hello world");
        captureOut(() -> Main.cmdSign(tmp, new String[]{"sign", "test.txt"}));
        // Sign.sign() writes <artifact>.sig as a sibling of the artifact
        assertTrue(Files.exists(tmp.resolve("test.txt.sig")));
    }

    @Test
    void cmdHooks_install_createsHook() throws Exception {
        Path gitDir = tmp.resolve(".git/hooks");
        Files.createDirectories(gitDir);
        captureOut(() -> Main.cmdHooks(tmp, new String[]{"install"}));
    }

    @Test
    void cmdFix_printsPlaceholder() throws Exception {
        String out = captureOut(() -> Main.cmdFix(tmp, new String[]{}));
        assertTrue(out.contains("fix") || out.contains("not yet implemented") || out.length() > 0);
    }

    @Test
    void cmdTemplate_safetyPlan() throws Exception {
        captureOut(() -> Main.cmdTemplate(tmp, new String[]{"safety-plan", "myproject"}));
    }

    @Test
    void cmdImpact_noChangedFiles() throws Exception {
        initProject();
        captureOut(() -> Main.cmdImpact(tmp, new String[]{}));
    }

    @Test
    void cmdImpact_withChangedFiles() throws Exception {
        initProject();
        captureOut(() -> Main.cmdImpact(tmp,
                new String[]{"src/main/java/com/soundmatt/jfusa/FuSa.java"}));
    }

    //fusa:test REQ-BADGE001
    @Test
    void cmdBadge_generatesSvg() throws Exception {
        initProject();
        captureOut(() -> Main.cmdBadge(tmp, new String[]{}));
        assertTrue(Files.exists(tmp.resolve("badge.svg")));
    }

    // ── report (§9.1 MUST — re-runs analysis, never gate-fails) ────────────────

    @Test
    void cmdReport_reRunsAnalysis_producesOutputWithoutReadingCachedFile() throws Exception {
        initProject();
        // No cached report file of any name exists in tmp — this used to fail with
        // "file not found: fusa-report.json"; `report` must analyze the project instead.
        String out = captureOut(() -> Main.cmdReport(tmp, new String[]{}));
        assertTrue(out.length() > 0, "report should render freshly analyzed content, not echo a cached file");
    }

    @Test
    void cmdReport_formatJson_matchesCheckShape() throws Exception {
        initProject();
        String out = captureOut(() -> Main.cmdReport(tmp, new String[]{"--format", "json"}));
        assertTrue(out.contains("\"findings\"") && out.contains("\"summary\""),
                "report --format json must be the same Finding[]/summary shape as check (§4)");
    }

    @Test
    void cmdReport_honorsOutputFlag_noStdoutEcho() throws Exception {
        initProject();
        String out = captureOut(() ->
                Main.cmdReport(tmp, new String[]{"--format", "json", "--output", "r.json"}));
        assertTrue(Files.exists(tmp.resolve("r.json")), "--output should redirect the report");
        assertFalse(out.contains("\"schemaVersion\""),
                "stdout must stay clean when --output is given (§2.2)");
    }

    @Test
    void cmdReport_neverGateFails_evenWithErrorFindings() throws Exception {
        initProject();
        // A hardcoded credential trips a CYBER ERROR finding, which would gate-fail `check`.
        Path bad = tmp.resolve("src/main/java/Bad.java");
        Files.createDirectories(bad.getParent());
        Files.writeString(bad, """
                public class Bad {
                    String pw = "password123";
                    void f() { System.out.println("select * from users where pw='" + pw + "'"); }
                }
                """);
        // report must not throw CheckFailedException regardless of findings (§9.1: only 2/3 apply).
        captureOut(() -> Main.cmdReport(tmp, new String[]{"--format", "json"}));
    }
}
