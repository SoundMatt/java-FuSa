package com.soundmatt.jfusa.cmd;

import com.soundmatt.jfusa.FuSa;
import static com.soundmatt.jfusa.FuSa.*;
import com.soundmatt.jfusa.analyze.AnalyzeRules;
import com.soundmatt.jfusa.auditpack.AuditPack;
import com.soundmatt.jfusa.badge.Badge;
import com.soundmatt.jfusa.boundary.Boundary;
import com.soundmatt.jfusa.comp.Comp;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.coupling.Coupling;
import com.soundmatt.jfusa.coverage.Coverage;
import com.soundmatt.jfusa.cyber.CyberRules;
import com.soundmatt.jfusa.diff.Diff;
import com.soundmatt.jfusa.disposition.Disposition;
import com.soundmatt.jfusa.do178.Do178;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.fmea.Fmea;
import com.soundmatt.jfusa.hara.Hara;
import com.soundmatt.jfusa.hooks.Hooks;
import com.soundmatt.jfusa.iec61508.Iec61508;
import com.soundmatt.jfusa.iec62443.Iec62443;
import com.soundmatt.jfusa.impact.Impact;
import com.soundmatt.jfusa.internal.Json;
import com.soundmatt.jfusa.iso21434.Iso21434;
import com.soundmatt.jfusa.iso26262.Iso26262;
import com.soundmatt.jfusa.lint.LintRules;
import com.soundmatt.jfusa.metrics.Metrics;
import com.soundmatt.jfusa.misra.Misra;
import com.soundmatt.jfusa.pr.ProblemReport;
import com.soundmatt.jfusa.qualify.Qualify;
import com.soundmatt.jfusa.qualitybar.QualityBar;
import com.soundmatt.jfusa.release.Release;
import com.soundmatt.jfusa.report.Report;
import com.soundmatt.jfusa.safetycase.SafetyCase;
import com.soundmatt.jfusa.sas.Sas;
import com.soundmatt.jfusa.sci.Sci;
import com.soundmatt.jfusa.sign.Sign;
import com.soundmatt.jfusa.slsa.Slsa;
import com.soundmatt.jfusa.tara.Tara;
import com.soundmatt.jfusa.template.Template;
import com.soundmatt.jfusa.trace.Trace;
import com.soundmatt.jfusa.unece.Unece;
import com.soundmatt.jfusa.verify.Verify;
import com.soundmatt.jfusa.vuln.Vuln;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * jfusa CLI entry point — dispatches all 45 sub-commands.
 *
 * Exit codes: 0=OK, 1=gate-fail, 2=usage-error, 3=runtime-error
 */
public final class Main {

    private Main() {}

    // Trigger class loading of all rule packages so their static initializers
    // register rules into Engine.DEFAULT (Java has no blank-import side-effects).
    static {
        LintRules.activate();
        AnalyzeRules.activate();
        CyberRules.activate();
        Trace.activate();
        Verify.activate();
        Release.activate();
        Qualify.activate();
        Slsa.activate();
        Iec62443.activate();
        Coverage.activate();
        Comp.activate();
        Misra.activate();
        Vuln.activate();
    }

    public static void main(String[] args) {
        if (args.length == 0) { usage(); System.exit(EXIT_USAGE); }

        // §2.6 global --no-color flag — scan all args before dispatch
        if (hasFlag(args, "--no-color")) System.setProperty("jfusa.nocolor", "1");

        String cmd = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        // §2.2 shared --dir flag — MUST apply to every command; default is cwd.
        Path root = resolveRoot(rest);
        rest = stripFlagWithValue(rest, "--dir");

        try {
            switch (cmd) {
                case "init"         -> cmdInit(root, rest);
                case "check"        -> cmdCheck(root, rest);
                case "lint"         -> cmdLint(root, rest);
                case "analyze"      -> cmdAnalyze(root, rest);
                case "cyber"        -> cmdCyber(root, rest);
                case "report"       -> cmdReport(root, rest);
                case "template"     -> cmdTemplate(root, rest);
                case "trace"        -> cmdTrace(root, rest);
                case "verify"       -> cmdVerify(root, rest);
                case "release"      -> cmdRelease(root, rest);
                case "qualify"      -> cmdQualify(root, rest);
                case "safety-case"  -> cmdSafetyCase(root, rest);
                case "fmea"         -> cmdFmea(root, rest);
                case "boundary"     -> cmdBoundary(root, rest);
                case "coupling"     -> cmdCoupling(root, rest);
                case "tara"         -> cmdTara(root, rest);
                case "hara"         -> cmdHara(root, rest);
                case "vuln"         -> cmdVuln(root, rest);
                case "audit-pack"   -> cmdAuditPack(root, rest);
                case "diff"         -> cmdDiff(root, rest);
                case "badge"        -> cmdBadge(root, rest);
                case "req"          -> cmdReq(root, rest);
                case "fix"          -> cmdFix(root, rest);
                case "hooks"        -> cmdHooks(root, rest);
                case "sign"         -> cmdSign(root, rest);
                case "do178"        -> cmdDo178(root, rest);
                case "iso21434"     -> cmdIso21434(root, rest);
                case "iso26262"     -> cmdIso26262(root, rest);
                case "iec61508"     -> cmdIec61508(root, rest);
                case "iec62443"     -> cmdIec62443(root, rest);
                case "unece"        -> cmdUnece(root, rest);
                case "slsa"         -> cmdSlsa(root, rest);
                case "sas"          -> cmdSas(root, rest);
                case "sci"          -> cmdSci(root, rest);
                case "coverage"     -> cmdCoverage(root, rest);
                case "comp"         -> cmdComp(root, rest);
                case "pr"           -> cmdPr(root, rest);
                case "disposition"  -> cmdDisposition(root, rest);
                case "impact"       -> cmdImpact(root, rest);
                case "metrics"      -> cmdMetrics(root, rest);
                case "misra"        -> cmdMisra(root, rest);
                case "capabilities" -> cmdCapabilitiesFmt(flagValue(rest, "--format", "text"));
                case "version"      -> {
                    if (hasFlag(rest, "--format") && "json".equals(flagValue(rest, "--format", "text")))
                        cmdVersionJson();
                    else cmdVersion();
                }
                case "--version", "-v" -> cmdVersion();
                case "--help", "-h"    -> { usage(); }
                default -> {
                    System.err.println("jfusa: unknown command '" + cmd + "'");
                    System.err.println("Run 'jfusa --help' for usage.");
                    System.exit(EXIT_USAGE);
                }
            }
        } catch (NoConfigException e) {
            emitJsonError(ERR_NO_CONFIG, "no .fusa.json found — run 'jfusa init' first");
            System.exit(EXIT_RUNTIME);
        } catch (InvalidConfigException e) {
            emitJsonError(ERR_INVALID_CONFIG, e.getMessage());
            System.exit(EXIT_RUNTIME);
        } catch (CheckFailedException e) {
            System.exit(EXIT_GATE_FAIL);
        } catch (Exception e) {
            emitJsonError(ERR_INTERNAL, e.getMessage() != null ? e.getMessage() : e.getClass().getName());
            if (System.getenv("JFUSA_DEBUG") != null) e.printStackTrace();
            System.exit(EXIT_RUNTIME);
        }
    }

    // ── §3.2 structured error to stderr ──────────────────────────────────────

    // §3.2 MUST: error.code is one of this closed, hyphenated enum (never underscores).
    static final String ERR_NO_CONFIG      = "no-config";
    static final String ERR_INVALID_CONFIG = "invalid-config";
    static final String ERR_UNSUPPORTED    = "unsupported";
    static final String ERR_INTERNAL       = "internal";

    static void emitJsonError(String code, String message) {
        String safeMsg = message == null ? "" : message.replace("\\", "\\\\").replace("\"", "\\\"");
        System.err.println("{\"error\":{\"code\":\"" + code + "\",\"message\":\"" + safeMsg + "\"}}");
    }

    // -------------------------------------------------------------------------
    // Command implementations
    // -------------------------------------------------------------------------

    static void cmdInit(Path root, String[] args) throws IOException {
        String name = args.length > 0 ? args[0] : root.getFileName().toString();
        Path cfgPath = root.resolve(".fusa.json");
        if (Files.exists(cfgPath) && !hasFlag(args, "--force")) {
            System.out.println(".fusa.json already exists. Use --force to overwrite.");
            return;
        }
        Config cfg = Config.defaultConfig(name);
        Config.save(root, cfg);

        // Seed .fusa-reqs.json if missing
        Path reqs = root.resolve(".fusa-reqs.json");
        if (!Files.exists(reqs)) {
            var w = new Json.Writer();
            w.objectStart();
            w.field("schemaVersion", FuSa.SPEC_VERSION);
            w.field("kind", "requirements");
            w.field("tool", "java-FuSa");
            w.field("toolVersion", FuSa.VERSION);
            w.field("language", "java");
            w.field("generatedAt", java.time.Instant.now().toString());
            w.key("requirements"); w.arrayStart(); w.arrayEnd();
            w.objectEnd();
            Files.writeString(reqs, w.toPretty() + "\n");
        }
        System.out.println("Initialized jfusa project: " + name);
        System.out.println("  .fusa.json      — project configuration");
        System.out.println("  .fusa-reqs.json — requirements registry");
        System.out.println("\nNext: run 'jfusa check' to audit the project.");
    }

    static void cmdCheck(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "text");
        String output = flagValue(args, "--output", "");
        boolean failOnWarn = hasFlag(args, "--fail-on-warn");

        Engine.Result result = Engine.DEFAULT.run(root, cfg);
        Report report = new Report(result, cfg, root);
        String rendered = report.render(format);

        if (!output.isEmpty()) {
            Files.writeString(root.resolve(output), rendered);
            System.err.println("Report written to " + output);  // §2.2: progress on stderr only
        } else {
            System.out.print(rendered);
        }

        if (result.hasErrors() || (failOnWarn && result.hasWarnings())) {
            throw new CheckFailedException("gate check failed");
        }
    }

    static void cmdLint(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "text");
        String output = flagValue(args, "--output", "");
        Engine.Result result = Engine.DEFAULT.runFilter(root, cfg, r -> r.id().startsWith("LINT"));
        Report report = new Report(result, cfg, root);
        String rendered = report.render(format);
        if (!output.isEmpty()) {
            Files.writeString(root.resolve(output), rendered);
            System.err.println("Report written to " + output);
        } else {
            System.out.print(rendered);
        }
        if (result.hasErrors()) throw new CheckFailedException("lint check failed");
    }

    static void cmdAnalyze(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "text");
        String output = flagValue(args, "--output", "");
        Engine.Result result = Engine.DEFAULT.runFilter(root, cfg, r -> r.id().startsWith("ANA"));
        Report report = new Report(result, cfg, root);
        String rendered = report.render(format);
        if (!output.isEmpty()) {
            Files.writeString(root.resolve(output), rendered);
            System.err.println("Report written to " + output);
        } else {
            System.out.print(rendered);
        }
        if (result.hasErrors()) throw new CheckFailedException("analyze check failed");
    }

    static void cmdCyber(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "text");
        String output = flagValue(args, "--output", "");
        Engine.Result result = Engine.DEFAULT.runFilter(root, cfg, r -> r.id().startsWith("CYBER"));
        Report report = new Report(result, cfg, root);
        String rendered = report.render(format);
        if (!output.isEmpty()) {
            Files.writeString(root.resolve(output), rendered);
            System.err.println("Report written to " + output);
        } else {
            System.out.print(rendered);
        }
        if (result.hasErrors()) throw new CheckFailedException("cyber check failed");
    }

    static void cmdReport(Path root, String[] args) throws IOException {
        // §9.1 MUST: `report` re-runs analysis on the project root (same shape as `check`,
        // §4) — it does not read a cached report and has no --input flag. It never
        // gate-fails (only exit 2/3 apply), so --strict here is a usage error (SHOULD).
        if (hasFlag(args, "--strict")) {
            System.err.println("jfusa report: --strict is not supported — report never gate-fails (see 'jfusa check')");
            System.exit(EXIT_USAGE);
            return;
        }
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "text");
        String output = flagValue(args, "--output", "");

        Engine.Result result = Engine.DEFAULT.run(root, cfg);
        Report report = new Report(result, cfg, root);
        String rendered = report.render(format);

        if (!output.isEmpty()) {
            Files.writeString(root.resolve(output), rendered);
            System.err.println("Report written to " + output);  // §2.2: progress on stderr only
        } else {
            System.out.print(rendered);
        }
        // Never gate-fails: no CheckFailedException regardless of findings.
    }

    static void cmdTemplate(Path root, String[] args) throws IOException {
        if (args.length < 1) { System.err.println("Usage: jfusa template <kind> [name]"); System.exit(EXIT_USAGE); }
        String kind = args[0];
        String name = args.length > 1 ? args[1] : "project";
        Template.generate(root, kind, name);
    }

    static void cmdTrace(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "text");
        String output = flagValue(args, "--output", "");
        boolean strictHlrLlr = hasFlag(args, "--strict-hlr-llr");
        int funcCoverageThreshold = Integer.parseInt(flagValue(args, "--func-coverage", "0"));

        var matrix = Trace.buildMatrix(root, cfg);

        // HLR/LLR hierarchy validation
        List<Trace.Requirement> reqs = Trace.loadFullRequirements(root);
        boolean hasHierarchy = reqs.stream().anyMatch(Trace.Requirement::isLlr);
        Trace.HlrLlrResult hlrResult = null;
        if (hasHierarchy || strictHlrLlr) {
            hlrResult = Trace.validateHierarchy(reqs);
            if (hlrResult.hasViolations()) {
                String asil = cfg.project().asil();
                String dal  = cfg.project().dal();
                boolean isHighIntegrity = "ASIL-D".equalsIgnoreCase(asil) || "DAL-A".equalsIgnoreCase(dal)
                        || "DAL-B".equalsIgnoreCase(dal);
                if (strictHlrLlr || isHighIntegrity) {
                    System.err.println("jfusa trace: HLR/LLR hierarchy violations detected (fatal for " +
                            (strictHlrLlr ? "--strict-hlr-llr" : asil.isBlank() ? dal : asil) + ")");
                    for (String id : hlrResult.childlessHlrs())
                        System.err.println("  HLR " + id + " has no LLR children");
                    for (String id : hlrResult.orphanLlrs())
                        System.err.println("  LLR " + id + " references unknown parent");
                    throw new FuSa.CheckFailedException("HLR/LLR hierarchy validation failed");
                }
                // Warn only for lower integrity levels
                System.err.println("jfusa trace: WARNING — HLR/LLR hierarchy violations (use --strict-hlr-llr to fail)");
            }
        }

        String rendered;
        if ("json".equals(format)) {
            rendered = hlrResult != null ? Trace.renderJson(matrix, root, hlrResult) : Trace.renderJson(matrix, root);
        } else {
            rendered = hlrResult != null ? Trace.renderText(matrix, hlrResult) : Trace.renderText(matrix);
        }
        if (!output.isEmpty()) {
            Files.writeString(root.resolve(output), rendered + "\n");
            System.err.println("Trace written to " + output);
        } else {
            System.out.println(rendered);
        }

        // §1.4.1 / §5 --func-coverage N — percentage 0-100 of public functions carrying a
        // requirement tag; N=0 disables the gate (mirrors --req-coverage's semantics).
        if (hasFlag(args, "--func-coverage")) {
            Trace.FuncCoverageResult funcCov = Trace.computeFuncCoverage(root, cfg);
            System.err.printf("Function coverage: %d/%d public functions tagged (%.0f%%)%n",
                    funcCov.taggedFunctions(), funcCov.totalFunctions(), funcCov.percentage());
            if (funcCoverageThreshold > 0 && funcCov.percentage() < funcCoverageThreshold) {
                System.err.println("jfusa trace: function coverage " +
                        String.format("%.0f%%", funcCov.percentage()) +
                        " is below required --func-coverage " + funcCoverageThreshold + "%");
                throw new FuSa.CheckFailedException("function coverage gate failed");
            }
        }
    }

    static void cmdVerify(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        Verify.run(root, cfg);
    }

    static void cmdRelease(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String outputDir = flagValue(args, "--output-dir", "");
        Path target = outputDir.isEmpty() ? root : root.resolve(outputDir);
        Release.run(root, cfg, target);
    }

    static void cmdQualify(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        boolean full = hasFlag(args, "--full");
        // §2.2: empty here (not Qualify.QUALIFY_REPORT) so Qualify.run can tell whether
        // --output was explicitly given — that distinction gates the stdout echo below.
        String output = flagValue(args, "--output", "");
        String format = flagValue(args, "--format", "text");
        // Feature 2: qualification display options
        String method    = flagValue(args, "--qualification-method", "");
        String qualifier = flagValue(args, "--qualifier", "");
        String recordUri = flagValue(args, "--record-uri", "");
        // Feature 4: V&V independence options
        String implAuthor     = flagValue(args, "--implementation-author", "");
        String reviewer       = flagValue(args, "--independent-reviewer", "");
        String testExecutor   = flagValue(args, "--independent-test-executor", "");
        String achievableAsil = flagValue(args, "--achievable-asil", "");
        Qualify.QualifyOptions opts = new Qualify.QualifyOptions(
                method, qualifier, recordUri, implAuthor, reviewer, testExecutor, achievableAsil);
        Qualify.run(root, cfg, full, opts, output, format);
    }

    static void cmdSafetyCase(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "text");
        String output = flagValue(args, "--output", "");
        boolean strict = hasFlag(args, "--strict") || hasFlag(args, "--require-attestation");
        String project = cfg.project().name();
        String standard = cfg.project().standard().canonicalId();

        SafetyCase.SafetyCaseReport report = SafetyCase.build(root, project, standard);
        SafetyCase.writeJson(root, report, "json".equals(format) ? output : "");
        SafetyCase.writeMarkdown(root, report, project, standard);
        SafetyCase.writeMermaid(root, report);

        QualityBar.Result qb = QualityBar.evaluate(root, SafetyCase.SAFETY_CASE_JSON,
                SafetyCase.qualityBarFields(report.nodes()), report.attestation(),
                SafetyCase.substantiveContent(report.nodes(), report.edges()));
        System.err.print(QualityBar.renderText(qb));

        String rendered = switch (format) {
            case "json" -> null; // already written above
            case "mermaid" -> Files.readString(root.resolve(SafetyCase.SAFETY_CASE_MERMAID));
            case "md" -> Files.readString(root.resolve(SafetyCase.SAFETY_CASE_MD));
            default -> SafetyCase.renderText(report, project, standard);
        };
        if (rendered != null) {
            if (!output.isEmpty() && !"json".equals(format)) Files.writeString(root.resolve(output), rendered);
            else System.out.print(rendered);
        } else {
            System.out.println("safety-case written: " + SafetyCase.SAFETY_CASE_JSON);
        }

        gateQualityBar(qb, strict, "safety-case");
    }

    static void cmdFmea(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "json");
        String output = flagValue(args, "--output", "");
        int minCoverage = Integer.parseInt(flagValue(args, "--min-coverage", "0"));
        boolean strict = hasFlag(args, "--strict") || hasFlag(args, "--require-attestation");

        Fmea.FmeaReport report = Fmea.build(root, cfg);
        Fmea.writeJson(root, report, "json".equals(format) ? output : "");
        Fmea.writeCsv(root, report.entries());

        QualityBar.Result qb = QualityBar.evaluate(root, Fmea.FMEA_JSON, Fmea.qualityBarFields(report.entries()),
                report.attestation(), Fmea.substantiveContent(report.entries()));
        System.err.print(QualityBar.renderText(qb));

        if ("text".equals(format)) {
            String rendered = Fmea.renderText(report);
            if (!output.isEmpty()) Files.writeString(root.resolve(output), rendered);
            else System.out.print(rendered);
        } else if ("json".equals(format)) {
            System.out.println("fmea written: " + (output.isEmpty() ? Fmea.FMEA_JSON : output) + ", " + Fmea.FMEA_CSV);
        }

        if (minCoverage > 0 && report.summary().coveragePct() < minCoverage) {
            System.err.printf("jfusa fmea: coverage %.1f%% is below required --min-coverage %d%%%n",
                    report.summary().coveragePct(), minCoverage);
            throw new FuSa.CheckFailedException("fmea coverage gate failed");
        }
        gateQualityBar(qb, strict, "fmea");
    }

    static void cmdBoundary(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        Boundary.generate(root, cfg);
    }

    static void cmdCoupling(Path root, String[] args) throws IOException {
        Coupling.generate(root);
    }

    static void cmdTara(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "json");
        String output = flagValue(args, "--output", "");
        int minCoverage = Integer.parseInt(flagValue(args, "--min-coverage", "0"));
        boolean strict = hasFlag(args, "--strict") || hasFlag(args, "--require-attestation");
        String project = cfg.project().name();

        Tara.TaraReport report = Tara.build(root, project);
        Tara.writeJson(root, report, "json".equals(format) ? output : "");
        Tara.writeMarkdown(root, report, project);

        QualityBar.Result qb = QualityBar.evaluate(root, Tara.TARA_JSON, Tara.qualityBarFields(report.threats()),
                report.attestation(), Tara.substantiveContent(report.threats()));
        System.err.print(QualityBar.renderText(qb));

        if ("text".equals(format)) {
            String rendered = Tara.renderText(report);
            if (!output.isEmpty()) Files.writeString(root.resolve(output), rendered);
            else System.out.print(rendered);
        } else if ("json".equals(format)) {
            System.out.println("tara written: " + (output.isEmpty() ? Tara.TARA_JSON : output) + ", " + Tara.TARA_MD);
        }

        if (minCoverage > 0 && report.summary().coveragePct() < minCoverage) {
            System.err.printf("jfusa tara: coverage %.1f%% is below required --min-coverage %d%%%n",
                    report.summary().coveragePct(), minCoverage);
            throw new FuSa.CheckFailedException("tara coverage gate failed");
        }
        gateQualityBar(qb, strict, "tara");
    }

    static void cmdHara(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "text");
        String output = flagValue(args, "--output", "");
        boolean init = hasFlag(args, "--init");

        if (init) Hara.init(root, cfg.project().name(), cfg.project().standard().canonicalId());

        Path haraFile = root.resolve(Hara.HARA_FILE);
        if (!Files.exists(haraFile)) {
            if ("json".equals(format)) {
                emitJsonError(ERR_NO_CONFIG, "no " + Hara.HARA_FILE + " found — run 'jfusa hara --init' first");
                System.exit(EXIT_RUNTIME);
                return;
            }
            System.out.println("No " + Hara.HARA_FILE + " found. Run 'jfusa hara --init' to scaffold one.");
            return;
        }

        Hara.HaraDoc doc = Hara.load(root);
        Set<String> reqIds = Hara.loadReqIds(root);
        List<Hara.ValidationFinding> findings = Hara.validate(doc, reqIds);
        Hara.Completeness completeness = Hara.computeCompleteness(doc, reqIds);

        QualityBar.Result qb = QualityBar.evaluate(root, Hara.HARA_FILE, Hara.qualityBarFields(doc),
                doc.attestation(), Hara.substantiveContent(doc));
        System.err.print(QualityBar.renderText(qb));

        String rendered = "json".equals(format) ? Hara.renderJson(doc, completeness)
                : Hara.renderText(doc, findings, completeness);
        if (!output.isEmpty()) {
            Files.writeString(root.resolve(output), rendered + "\n");
            System.err.println("HARA written to " + output);
        } else {
            System.out.println(rendered);
        }

        boolean structuralGap = completeness.danglingReferences() > 0
                || completeness.safetyGoalsWithFssrRefs() < completeness.totalSafetyGoals();
        if (structuralGap) {
            System.err.println("jfusa hara: " + findings.size() + " validation finding(s) — "
                    + completeness.danglingReferences() + " dangling reference(s), "
                    + (completeness.totalSafetyGoals() - completeness.safetyGoalsWithFssrRefs())
                    + " safety goal(s) without fssrRefs");
            throw new FuSa.CheckFailedException("hara validation failed");
        }
        gateQualityBar(qb, hasFlag(args, "--strict") || hasFlag(args, "--require-attestation"), "hara");
    }

    /** Shared FUSA-STUB001/002 exit-code gating (§1.6.1/§1.6.2) for every artifact command. */
    static void gateQualityBar(QualityBar.Result qb, boolean strict, String commandName) {
        if (qb.hasBlockingError()) {
            System.err.println("jfusa " + commandName + ": FUSA-STUB001 placeholder text found — see above");
            throw new FuSa.CheckFailedException(commandName + " content-quality gate failed (FUSA-STUB001)");
        }
        if (strict && qb.hasUnsuppressedWarning()) {
            System.err.println("jfusa " + commandName + ": --strict/--require-attestation: unsuppressed "
                    + "FUSA-STUB002 warning(s) — see above");
            throw new FuSa.CheckFailedException(commandName + " content-quality gate failed (FUSA-STUB002, --strict)");
        }
    }

    static void cmdVuln(Path root, String[] args) throws IOException {
        Vuln.scan(root);
    }

    static void cmdAuditPack(Path root, String[] args) throws IOException {
        String output = flagValue(args, "--output", AuditPack.AUDIT_PACK_FILE);
        AuditPack.generate(root, output);
    }

    static void cmdDiff(Path root, String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("Usage: jfusa diff <before.json> <after.json>");
            System.exit(EXIT_USAGE);
        }
        Diff.DiffResult r = Diff.compare(root.resolve(args[0]), root.resolve(args[1]));
        System.out.println(Diff.renderText(r, args[0], args[1]));
    }

    static void cmdBadge(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        Engine.Result result = Engine.DEFAULT.run(root, cfg);
        com.soundmatt.jfusa.report.Report report = new com.soundmatt.jfusa.report.Report(result, cfg);
        String output = flagValue(args, "--output", "badge.svg");
        Badge.writeToFile(root, report, output);
        System.out.println("Badge written: " + output);
    }

    static void cmdReq(Path root, String[] args) throws IOException {
        if (args.length == 0) { System.err.println("Usage: jfusa req <list|add|show> [args]"); System.exit(EXIT_USAGE); }
        switch (args[0]) {
            case "list" -> {
                Path reqs = root.resolve(".fusa-reqs.json");
                if (!Files.exists(reqs)) { System.out.println("No .fusa-reqs.json"); return; }
                System.out.println(Files.readString(reqs));
            }
            case "add" -> {
                if (args.length < 3) { System.err.println("Usage: jfusa req add <id> <title>"); System.exit(EXIT_USAGE); }
                addRequirement(root, args[1], args[2]);
            }
            default -> System.err.println("Unknown req sub-command: " + args[0]);
        }
    }

    static void addRequirement(Path root, String id, String title) throws IOException {
        Path reqs = root.resolve(".fusa-reqs.json");
        String existing = Files.exists(reqs) ? Files.readString(reqs) : "{\"schema\":\"x-fusa-reqs-1.0\",\"requirements\":[]}";
        // Append new requirement — simple JSON manipulation
        String newEntry = String.format("{\"id\":\"%s\",\"title\":\"%s\",\"status\":\"open\"}", id, title.replace("\"", "\\\""));
        String updated = existing.trim();
        if (updated.endsWith("]}")) {
            int lastBracket = updated.lastIndexOf(']');
            boolean empty = updated.substring(0, lastBracket).trim().endsWith("[");
            updated = updated.substring(0, lastBracket) + (empty ? "" : ",") + newEntry + "]}";
        }
        Files.writeString(reqs, updated);
        System.out.println("Requirement " + id + " added.");
    }

    static void cmdFix(Path root, String[] args) throws IOException {
        System.out.println("jfusa fix: Auto-fix is not yet implemented.");
        System.out.println("Tip: run 'jfusa lint' or 'jfusa check' to see findings, then fix manually.");
    }

    static void cmdHooks(Path root, String[] args) throws IOException {
        if (args.length == 0) { System.err.println("Usage: jfusa hooks <install|remove>"); System.exit(EXIT_USAGE); }
        switch (args[0]) {
            case "install" -> Hooks.install(root);
            case "remove"  -> Hooks.remove(root);
            default -> System.err.println("Unknown hooks sub-command: " + args[0]);
        }
    }

    static void cmdSign(Path root, String[] args) throws IOException {
        if (args.length < 2) { System.err.println("Usage: jfusa sign <sign|verify> <file>"); System.exit(EXIT_USAGE); }
        Path keyFile = root.resolve(".fusa-signing.key");
        switch (args[0]) {
            case "generate-key" -> {
                Sign.generateKey(keyFile);
                System.out.println("Signing key generated: " + keyFile);
            }
            case "sign" -> {
                if (!Files.exists(keyFile)) Sign.generateKey(keyFile);
                Sign.sign(root.resolve(args[1]), keyFile);
                System.out.println("Signed: " + args[1]);
            }
            case "verify" -> {
                boolean ok = Sign.verify(root.resolve(args[1]), keyFile);
                System.out.println(args[1] + ": " + (ok ? "VALID" : "INVALID"));
                if (!ok) System.exit(EXIT_GATE_FAIL);
            }
            default -> System.err.println("Unknown sign sub-command: " + args[0]);
        }
    }

    static void cmdDo178(Path root, String[] args) throws IOException {
        String dal  = flagValue(args, "--dal",  "DAL-C");
        String format = flagValue(args, "--format", "text");
        if ("text".equals(format)) System.out.println(Do178.renderText(dal));
        else { Do178.generate(root, dal); System.out.println("Written: " + Do178.GAP_REPORT); }
    }

    static void cmdIso21434(Path root, String[] args) throws IOException {
        String cal  = flagValue(args, "--cal",  "CAL-3");
        String format = flagValue(args, "--format", "text");
        if ("text".equals(format)) System.out.println(Iso21434.renderText(cal));
        else { Iso21434.generate(root, cal); System.out.println("Written: " + Iso21434.GAP_REPORT); }
    }

    static void cmdIso26262(Path root, String[] args) throws IOException {
        String asil = flagValue(args, "--asil", "ASIL-B");
        String format = flagValue(args, "--format", "text");
        if ("text".equals(format)) System.out.println(Iso26262.renderText(asil));
        else { Iso26262.generate(root, asil); System.out.println("Written: " + Iso26262.GAP_REPORT); }
    }

    static void cmdIec61508(Path root, String[] args) throws IOException {
        String sil  = flagValue(args, "--sil",  "SIL-2");
        String format = flagValue(args, "--format", "text");
        if ("text".equals(format)) System.out.println(Iec61508.renderText(sil));
        else { Iec61508.generate(root, sil); System.out.println("Written: " + Iec61508.GAP_REPORT); }
    }

    static void cmdIec62443(Path root, String[] args) throws IOException {
        String sl = flagValue(args, "--sl", "SL-2");
        String format = flagValue(args, "--format", "text");
        if (!"text".equals(format)) {
            Iec62443.generate(root, sl);
            System.out.println("Written: " + Iec62443.GAP_REPORT);
        } else {
            Config cfg = Config.load(root);
            Engine.Result result = Engine.DEFAULT.runFilter(root, cfg,
                    r -> r.id().startsWith("IEC62443"));
            Report report = new Report(result, cfg, root);
            System.out.print(report.render("text"));
        }
    }

    static void cmdUnece(Path root, String[] args) throws IOException {
        String format = flagValue(args, "--format", "text");
        if ("text".equals(format)) System.out.println(Unece.renderText());
        else Unece.generate(root);
    }

    static void cmdSlsa(Path root, String[] args) throws IOException {
        String level = flagValue(args, "--level", "L2");
        String format = flagValue(args, "--format", "text");
        Slsa.generateGapReport(root, level, format);
    }

    static void cmdSas(Path root, String[] args) throws IOException {
        String format = flagValue(args, "--format", "md");
        String output = flagValue(args, "--output", "");
        boolean strict = hasFlag(args, "--strict") || hasFlag(args, "--require-attestation");

        Sas.SasReport report = Sas.build(root);
        Sas.writeMarkdown(root, report);
        if ("json".equals(format)) Sas.writeJson(root, report, output);
        else Sas.writeJson(root, report, Sas.SAS_JSON); // §9.3: sas.json is always also written

        QualityBar.Result qb = QualityBar.evaluate(root, Sas.SAS_JSON, Sas.qualityBarFields(report.checklist()),
                report.attestation(), Sas.substantiveContent(report.checklist()));
        System.err.print(QualityBar.renderText(qb));

        System.out.println("SAS generated: " + Sas.SAS_MD + " (" + report.summary().present() + "/"
                + report.summary().total() + " items present)");
        gateQualityBar(qb, strict, "sas");
    }

    static void cmdSci(Path root, String[] args) throws IOException {
        String format = flagValue(args, "--format", "json");
        String output = flagValue(args, "--output", "");
        if ("markdown".equals(format)) {
            Sci.generate(root, format);
            System.out.println("SCI generated: " + Sci.SCI_MD);
        } else {
            Sci.generateJson(root, output);
            System.out.println("SCI generated: " + (output.isEmpty() ? Sci.SCI_JSON : output));
        }
    }

    static void cmdCoverage(Path root, String[] args) throws IOException {
        Path jacoco = root.resolve("target/site/jacoco/jacoco.xml");
        Coverage.CoverageReport cov = Coverage.parse(jacoco);
        System.out.printf("Coverage: stmt=%.1f%% branch=%.1f%% method=%.1f%%%n",
                cov.statementPct(), cov.branchPct(), cov.methodPct());

        // Feature 3: MC/DC coverage
        boolean mcdc = hasFlag(args, "--mcdc");
        if (mcdc) {
            String mcdcFilePath = flagValue(args, "--mcdc-file", "");
            Path mcdcFile = mcdcFilePath.isEmpty()
                    ? root.resolve("target/mcdc.json") : root.resolve(mcdcFilePath);
            Coverage.McdcReport mcdcReport = Coverage.parseMcdc(mcdcFile);
            System.out.printf("MC/DC: %d/%d functions pass  [%s]%n",
                    mcdcReport.passingFunctions(), mcdcReport.totalFunctions(),
                    mcdcReport.gatePass() ? "PASS" : "FAIL");
            if (!mcdcReport.failingFunctions().isEmpty()) {
                System.err.println("MC/DC gate failures:");
                for (String fn : mcdcReport.failingFunctions())
                    System.err.println("  FAIL  " + fn);
                throw new FuSa.CheckFailedException("MC/DC coverage gate failed");
            }
        }
    }

    static void cmdComp(Path root, String[] args) throws IOException {
        String dal = flagValue(args, "--dal", null);
        String threshStr = flagValue(args, "--threshold", null);
        int threshold = dal != null ? Comp.thresholdForDal(dal)
                : (threshStr != null ? Integer.parseInt(threshStr) : Comp.DEFAULT_THRESHOLD);
        String format = flagValue(args, "--format", "text");
        if ("json".equals(format)) {
            Comp.generate(root, threshold, dal);
        } else {
            List<Comp.MethodComplexity> results = Comp.analyze(root);
            long violations = results.stream().filter(r -> r.complexity() > threshold).count();
            System.out.printf("Complexity analysis (threshold=%d%s): %d function(s), %d violation(s)%n",
                    threshold, dal != null ? " / " + dal : "", results.size(), violations);
            results.stream().filter(r -> r.complexity() > threshold)
                    .forEach(r -> System.out.printf("  FAIL  %s:%d  %s  complexity=%d%n",
                            r.file(), r.line(), r.method(), r.complexity()));
            if (violations > 0) throw new FuSa.CheckFailedException("complexity gate failed");
        }
    }

    static void cmdPr(Path root, String[] args) throws IOException {
        if (args.length == 0) { System.err.println("Usage: jfusa pr <init|add|close|list>"); System.exit(EXIT_USAGE); }
        switch (args[0]) {
            case "init"  -> ProblemReport.init(root);
            case "list"  -> System.out.print(ProblemReport.list(root));
            case "add"   -> {
                if (args.length < 4) { System.err.println("Usage: jfusa pr add <id> <title> <severity>"); System.exit(EXIT_USAGE); }
                ProblemReport.add(root, args[1], args[2], args[3]);
            }
            case "close" -> {
                if (args.length < 3) { System.err.println("Usage: jfusa pr close <id> <resolution>"); System.exit(EXIT_USAGE); }
                ProblemReport.close(root, args[1], args[2]);
            }
            default -> System.err.println("Unknown pr sub-command: " + args[0]);
        }
    }

    static void cmdDisposition(Path root, String[] args) throws IOException {
        if (args.length == 0) { System.err.println("Usage: jfusa disposition <list|add|update>"); System.exit(EXIT_USAGE); }
        switch (args[0]) {
            case "list" -> System.out.print(Disposition.list(root));
            case "add"  -> {
                if (args.length < 5) { System.err.println("Usage: jfusa disposition add <ruleId> <file> <action> <rationale>"); System.exit(EXIT_USAGE); }
                Disposition.add(root, args[1], args[2], args[3], args[4]);
            }
            default -> System.err.println("Unknown disposition sub-command: " + args[0]);
        }
    }

    static void cmdImpact(Path root, String[] args) throws IOException {
        List<String> changed = args.length > 0
                ? Arrays.asList(args)
                : gitChangedFiles(root);
        Impact.generate(root, changed);
    }

    static void cmdMetrics(Path root, String[] args) throws IOException {
        if (args.length > 0 && "record".equals(args[0])) {
            Config cfg = Config.load(root);
            Engine.Result result = Engine.DEFAULT.run(root, cfg);
            Metrics.record(root, new Report(result, cfg));
        } else {
            System.out.print(Metrics.show(root));
        }
    }

    static void cmdMisra(Path root, String[] args) throws IOException {
        String format = flagValue(args, "--format", "json");
        if ("text".equals(format)) {
            List<Object[]> hits = Misra.scan(root);
            hits.forEach(h -> System.out.printf("%s  %s:%d  %s%n", h[0], h[1], h[2], h[3]));
        } else {
            Misra.generate(root);
            System.out.println("MISRA report written: " + Misra.MISRA_JSON);
        }
    }

    static void cmdCapabilitiesFmt(String format) {
        if ("json".equals(format)) {
            var w = new Json.Writer();
            w.objectStart();
            w.field("schemaVersion", FuSa.SPEC_VERSION);
            w.field("kind", "capabilities");
            w.field("tool", "java-FuSa");
            w.field("toolVersion", FuSa.VERSION);
            w.field("language", "java");
            w.field("generatedAt", java.time.Instant.now().toString());
            w.field("specVersion", FuSa.SPEC_VERSION);
            w.key("commands"); w.arrayStart();
            for (String c : List.of("version","capabilities","init","check","lint","analyze",
                    "cyber","report","template","trace","verify","release","qualify",
                    "safety-case","fmea","boundary","coupling","tara","hara","vuln",
                    "audit-pack","diff","badge","req","fix","hooks","sign","do178",
                    "iso21434","iso26262","iec61508","iec62443","unece","slsa","sas",
                    "sci","coverage","comp","pr","disposition","impact","metrics","misra")) {
                w.value(c);
            }
            w.arrayEnd();
            w.key("formats"); w.objectStart();
            w.key("check"); w.arrayStart(); w.value("text"); w.value("json"); w.value("html"); w.value("sarif"); w.arrayEnd();
            w.key("trace"); w.arrayStart(); w.value("text"); w.value("json"); w.arrayEnd();
            w.key("report"); w.arrayStart(); w.value("text"); w.value("json"); w.value("html"); w.value("sarif"); w.arrayEnd();
            w.key("comp"); w.arrayStart(); w.value("text"); w.value("json"); w.arrayEnd();
            w.objectEnd();
            w.key("standards"); w.arrayStart();
            for (String s : List.of("iso26262","iec61508","do178c","iso21434","iec62443-4-1","unece-r155","slsa")) w.value(s);
            w.arrayEnd();
            w.objectEnd();
            System.out.println(w.toPretty());
        } else {
            System.out.println("jfusa " + FuSa.VERSION + " (x-FuSa spec " + FuSa.SPEC_VERSION + ")");
            System.out.println();
            System.out.println("Rule packages:");
            Engine.DEFAULT.rules().forEach(r ->
                    System.out.printf("  %-14s %s%n", r.id(), r.description()));
            System.out.println();
            System.out.printf("Total rules registered: %d%n", Engine.DEFAULT.rules().size());
        }
    }

    static void cmdVersion() {
        System.out.println("jfusa " + FuSa.VERSION);
    }

    static void cmdVersionJson() {
        System.out.printf("{\"tool\":\"java-FuSa\",\"version\":\"%s\",\"specVersion\":\"%s\"}%n",
                FuSa.VERSION, FuSa.SPEC_VERSION);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    static Path cwd() {
        return Paths.get(System.getProperty("user.dir", ".")).toAbsolutePath().normalize();
    }

    /** §2.2 `--dir <path>` — MUST apply to every command; default (no flag) is cwd. */
    static Path resolveRoot(String[] args) {
        String dir = flagValue(args, "--dir", "");
        return dir.isEmpty() ? cwd() : Paths.get(dir).toAbsolutePath().normalize();
    }

    /** Removes a flag (and its value, in either "--flag value" or "--flag=value" form) from args. */
    static String[] stripFlagWithValue(String[] args, String flag) {
        List<String> out = new java.util.ArrayList<>(args.length);
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals(flag)) { i++; continue; }
            if (args[i].startsWith(flag + "=")) continue;
            out.add(args[i]);
        }
        return out.toArray(new String[0]);
    }

    static boolean hasFlag(String[] args, String flag) {
        for (String a : args) if (a.equals(flag)) return true;
        return false;
    }

    static String flagValue(String[] args, String flag, String def) {
        // The "--flag=value" form is checked against every arg, including the last one — the
        // previous "i < args.length - 1" bound skipped it entirely when the equals-form flag was
        // the final argument (e.g. "check --format=json --output=report.json", exactly the shape
        // ci.yml's steps use), silently falling back to def instead of the given value.
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith(flag + "=")) return args[i].substring(flag.length() + 1);
            if (args[i].equals(flag) && i + 1 < args.length) return args[i + 1];
        }
        return def;
    }

    static List<String> gitChangedFiles(Path root) {
        try {
            Process p = new ProcessBuilder("git", "diff", "--name-only", "HEAD")
                    .directory(root.toFile()).start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            return Arrays.stream(out.split("\n")).filter(s -> !s.isBlank()).toList();
        } catch (Exception e) {
            return List.of();
        }
    }

    static void usage() {
        System.out.println("""
                jfusa — Java Functional Safety Tool Suite (x-FuSa spec v""" + FuSa.SPEC_VERSION + """
                )
                Version: """ + FuSa.VERSION + """


                Usage: jfusa <command> [flags]

                Core Commands:
                  init           Initialise .fusa.json and .fusa-reqs.json
                  check          Run all rules and produce a report
                  lint           Run Java coding rules (LINT001-010)
                  analyze        Run static analysis rules (ANA001-006)
                  cyber          Run CWE-mapped security rules (CYBER001-020)
                  report         Render or convert an existing report
                  template       Generate safety plan, HARA, test evidence templates

                Analysis & Evidence:
                  trace          Requirement ↔ code traceability matrix
                  verify         Generate .fusa-evidence.json
                  release        Generate SBOM (SPDX 2.3) + SLSA provenance
                  qualify        Run tool qualification suite
                  safety-case    Generate GSN safety-case.{json,md,mermaid}
                  fmea           Generate dFMEA (fmea.{json,csv})
                  boundary       Package dependency boundary graph
                  coupling       Data/control coupling report
                  tara           TARA per ISO 21434 Chapter 9
                  hara           HARA per ISO 26262-3
                  vuln           Dependency vulnerability scan
                  audit-pack     ZIP all evidence artifacts
                  diff           Compare two JSON reports by fingerprint
                  badge          Generate SVG badge
                  impact         Change impact analysis

                Compliance:
                  do178          DO-178C gap report
                  iso21434       ISO 21434 gap report
                  iso26262       ISO 26262 gap report
                  iec61508       IEC 61508 gap report
                  iec62443       IEC 62443 check
                  unece          UN R.155 check
                  slsa           SLSA L2/L3 check
                  sas            Software Accomplishment Summary (DO-178C §11.20)
                  sci            Software Configuration Index (DO-178C §11.16)
                  coverage       Show JaCoCo coverage metrics
                  comp           Cyclomatic complexity analysis
                  misra          MISRA Java 2023 alignment report

                Management:
                  req            Manage .fusa-reqs.json
                  pr             Problem report log (DO-178C §11.17)
                  disposition    Manage finding dispositions
                  metrics        Track safety metrics over time
                  sign           HMAC-SHA256 file signing/verification
                  hooks          Install/remove git pre-commit hook
                  fix            (future) Auto-fix findings

                Info:
                  capabilities   List all registered rules
                  version        Print version

                Flags:
                  --dir=<path>                               Project root (default: cwd)
                  --format=<text|json|html|sarif|markdown>  Output format
                  --output=<file>                            Write to file
                  --fail-on-warn                             Exit 1 on warnings
                  --force                                    Overwrite existing files

                Environment:
                  NO_COLOR=1       Disable ANSI colours
                  JFUSA_DEBUG=1    Print stack traces on error
                """);
    }
}
