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

        String cmd = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        Path root = cwd();

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
            System.err.println("jfusa: no .fusa.json found — run 'jfusa init' first");
            System.exit(EXIT_RUNTIME);
        } catch (InvalidConfigException e) {
            System.err.println("jfusa: invalid config — " + e.getMessage());
            System.exit(EXIT_RUNTIME);
        } catch (CheckFailedException e) {
            System.exit(EXIT_GATE_FAIL);
        } catch (Exception e) {
            System.err.println("jfusa: runtime error — " + e.getMessage());
            if (System.getenv("JFUSA_DEBUG") != null) e.printStackTrace();
            System.exit(EXIT_RUNTIME);
        }
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
        Report report = new Report(result, cfg);
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
        Engine.Result result = Engine.DEFAULT.runFilter(root, cfg,
                r -> r.id().startsWith("LINT"));
        Report report = new Report(result, cfg);
        System.out.print(report.render(format));
        if (result.hasErrors()) throw new CheckFailedException("lint check failed");
    }

    static void cmdAnalyze(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "text");
        Engine.Result result = Engine.DEFAULT.runFilter(root, cfg,
                r -> r.id().startsWith("ANA"));
        Report report = new Report(result, cfg);
        System.out.print(report.render(format));
        if (result.hasErrors()) throw new CheckFailedException("analyze check failed");
    }

    static void cmdCyber(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        String format = flagValue(args, "--format", "text");
        Engine.Result result = Engine.DEFAULT.runFilter(root, cfg,
                r -> r.id().startsWith("CYBER"));
        Report report = new Report(result, cfg);
        System.out.print(report.render(format));
        if (result.hasErrors()) throw new CheckFailedException("cyber check failed");
    }

    static void cmdReport(Path root, String[] args) throws IOException {
        String src = args.length > 0 && !args[0].startsWith("-") ? args[0] : "fusa-report.json";
        String format = flagValue(args, "--format", "text");
        Path srcPath = root.resolve(src);
        if (!Files.exists(srcPath)) {
            System.err.println("jfusa report: file not found: " + src);
            System.exit(EXIT_USAGE);
        }
        // Re-render an existing JSON report
        System.out.println("Rendering: " + src + " (format=" + format + ")");
        System.out.println(Files.readString(srcPath));
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
        var matrix = Trace.buildMatrix(root, cfg);
        String rendered = "json".equals(format) ? Trace.renderJson(matrix) : Trace.renderText(matrix);
        if (!output.isEmpty()) {
            Files.writeString(root.resolve(output), rendered + "\n");
            System.err.println("Trace written to " + output);
        } else {
            System.out.println(rendered);
        }
    }

    static void cmdVerify(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        Verify.run(root, cfg);
    }

    static void cmdRelease(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        Release.run(root, cfg);
    }

    static void cmdQualify(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        boolean full = hasFlag(args, "--full");
        Qualify.run(root, cfg, full);
    }

    static void cmdSafetyCase(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        SafetyCase.generate(root, cfg);
    }

    static void cmdFmea(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        Fmea.generate(root, cfg);
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
        Tara.generate(root, cfg.project().name());
    }

    static void cmdHara(Path root, String[] args) throws IOException {
        Config cfg = Config.load(root);
        Hara.init(root, cfg.project().name());
        System.out.println(Hara.show(root));
    }

    static void cmdVuln(Path root, String[] args) throws IOException {
        Vuln.scan(root);
    }

    static void cmdAuditPack(Path root, String[] args) throws IOException {
        AuditPack.generate(root);
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
        Config cfg = Config.load(root);
        Engine.Result result = Engine.DEFAULT.runFilter(root, cfg,
                r -> r.id().startsWith("IEC62443"));
        Report report = new Report(result, cfg);
        System.out.print(report.render("text"));
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
        Sas.generate(root);
    }

    static void cmdSci(Path root, String[] args) throws IOException {
        String format = flagValue(args, "--format", "json");
        Sci.generate(root, format);
        System.out.println("SCI generated: " + ("markdown".equals(format) ? Sci.SCI_MD : Sci.SCI_JSON));
    }

    static void cmdCoverage(Path root, String[] args) throws IOException {
        Path jacoco = root.resolve("target/site/jacoco/jacoco.xml");
        Coverage.CoverageReport cov = Coverage.parse(jacoco);
        System.out.printf("Coverage: stmt=%.1f%% branch=%.1f%% method=%.1f%%%n",
                cov.statementPct(), cov.branchPct(), cov.methodPct());
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

    static boolean hasFlag(String[] args, String flag) {
        for (String a : args) if (a.equals(flag)) return true;
        return false;
    }

    static String flagValue(String[] args, String flag, String def) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals(flag)) return args[i + 1];
            if (args[i].startsWith(flag + "=")) return args[i].substring(flag.length() + 1);
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
