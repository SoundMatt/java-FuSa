package com.soundmatt.jfusa.engine;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Rule execution engine.
 *
 * <p>Rules implement the {@link Rule} interface and are registered with a {@link Registry}.
 * Call {@link #run(Path, Config)} to execute all active rules against a project directory.
 */
public final class Engine {

    /** Package-level default registry; populated by built-in rule init. */
    public static final Registry DEFAULT = new Registry();

    static {
        DEFAULT.mustRegister(new RuleConfigPresent());
        DEFAULT.mustRegister(new RuleJavaProjectPresent());
        DEFAULT.mustRegister(new RuleLicensePresent());
        DEFAULT.mustRegister(new RuleReadmePresent());
        DEFAULT.mustRegister(new RuleCIPresent());
    }

    private final Registry registry;

    public Engine(Registry registry) { this.registry = registry; }
    public Engine() { this(DEFAULT); }

    // ── Result ────────────────────────────────────────────────────────────────

    public record Result(List<Finding> findings, List<String> errors) {

        public static Result empty() { return new Result(List.of(), List.of()); }

        //fusa:req REQ-ENG003
        public boolean hasErrors() {
            return findings.stream().anyMatch(f -> f.severity() == Severity.ERROR);
        }

        public boolean hasWarnings() {
            return findings.stream().anyMatch(f ->
                    f.severity() == Severity.WARNING || f.severity() == Severity.ERROR);
        }
    }

    // ── Run ───────────────────────────────────────────────────────────────────

    public Result run(Path projectRoot, Config cfg) {
        return runFilter(projectRoot, cfg, null);
    }

    //fusa:req REQ-ENG007
    public Result runFilter(Path projectRoot, Config cfg, Predicate<Rule> keep) {
        //fusa:req REQ-CFG007
        Set<String> excluded = cfg != null && cfg.rules() != null
                ? Set.copyOf(cfg.rules().exclude()) : Set.of();

        List<Finding> findings = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        for (Rule rule : registry.rules()) {
            if (excluded.contains(rule.id())) continue;
            if (keep != null && !keep.test(rule)) continue;
            try {
                List<Finding> ruleFindings = rule.run(projectRoot, cfg);
                if (ruleFindings != null) {
                    for (Finding f : ruleFindings) {
                        // Apply per-rule severity overrides from config.
                        if (cfg != null && cfg.rules().severity().containsKey(f.ruleId())) {
                            String sevStr = cfg.rules().severity().get(f.ruleId());
                            Severity sev = Severity.valueOf(sevStr);
                            f = Finding.builder(f.ruleId(), sev, f.message(), f.location())
                                    .category(f.category()).standard(f.standard()).clause(f.clause())
                                    .remediation(f.remediation()).disposition(f.disposition())
                                    .fingerprint(f.fingerprint()).build();
                        }
                        findings.add(f);
                    }
                }
            } catch (Exception e) {
                //fusa:req REQ-ENG002
                errors.add("rule " + rule.id() + ": " + e.getMessage());
            }
        }
        return new Result(Collections.unmodifiableList(findings),
                Collections.unmodifiableList(errors));
    }

    // ── Built-in rules (FUSA001–005) ──────────────────────────────────────────

    // FUSA001 — .fusa.json must be present.
    static final class RuleConfigPresent implements Rule {
        public String id() { return "FUSA001"; }
        public String description() { return "Project must have a .fusa.json configuration file."; }

        //fusa:req REQ-FUSA001
        public List<Finding> run(Path root, Config cfg) {
            if (!Files.exists(root.resolve(Config.CONFIG_FILE))) {
                return List.of(Finding.builder("FUSA001", Severity.ERROR,
                        "no .fusa.json found in project root",
                        new FuSa.Location(Config.CONFIG_FILE))
                        .category(FuSa.Category.config)
                        .remediation("run 'jfusa init' to create a starter configuration")
                        .build());
            }
            return List.of();
        }
    }

    // FUSA002 — pom.xml or build.gradle must be present.
    static final class RuleJavaProjectPresent implements Rule {
        public String id() { return "FUSA002"; }
        public String description() { return "Project must be a Java build project (pom.xml or build.gradle present)."; }

        //fusa:req REQ-FUSA002
        public List<Finding> run(Path root, Config cfg) {
            for (String name : List.of("pom.xml", "build.gradle", "build.gradle.kts")) {
                if (Files.exists(root.resolve(name))) return List.of();
            }
            return List.of(Finding.builder("FUSA002", Severity.ERROR,
                    "no Java build file found (pom.xml or build.gradle)",
                    new FuSa.Location("pom.xml"))
                    .category(FuSa.Category.config)
                    .remediation("initialise a Maven or Gradle project")
                    .build());
        }
    }

    // FUSA003 — LICENSE must be present.
    static final class RuleLicensePresent implements Rule {
        public String id() { return "FUSA003"; }
        public String description() { return "Project must have a LICENSE file for IP clarity in safety cases."; }

        //fusa:req REQ-FUSA003
        public List<Finding> run(Path root, Config cfg) {
            for (String name : List.of("LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE")) {
                if (Files.exists(root.resolve(name))) return List.of();
            }
            return List.of(Finding.builder("FUSA003", Severity.WARNING,
                    "no LICENSE file found",
                    new FuSa.Location("LICENSE"))
                    .category(FuSa.Category.config)
                    .remediation("add a LICENSE file to clarify IP ownership for assessors")
                    .build());
        }
    }

    // FUSA004 — README must be present.
    static final class RuleReadmePresent implements Rule {
        public String id() { return "FUSA004"; }
        public String description() { return "Project must have a README for assessor orientation."; }

        //fusa:req REQ-FUSA004
        public List<Finding> run(Path root, Config cfg) {
            for (String name : List.of("README.md", "README.txt", "README")) {
                if (Files.exists(root.resolve(name))) return List.of();
            }
            return List.of(Finding.builder("FUSA004", Severity.WARNING,
                    "no README file found",
                    new FuSa.Location("README.md"))
                    .category(FuSa.Category.config)
                    .remediation("add a README.md describing the project's safety context")
                    .build());
        }
    }

    // FUSA005 — CI configuration must be present.
    static final class RuleCIPresent implements Rule {
        public String id() { return "FUSA005"; }
        public String description() { return "Project must have CI configuration for automated evidence generation."; }

        //fusa:req REQ-FUSA005
        public List<Finding> run(Path root, Config cfg) throws Exception {
            for (String rel : List.of(".github/workflows", ".gitlab-ci.yml",
                    "Jenkinsfile", ".circleci", ".travis.yml", "azure-pipelines.yml")) {
                if (Files.exists(root.resolve(rel))) return List.of();
            }
            return List.of(Finding.builder("FUSA005", Severity.WARNING,
                    "no CI configuration found",
                    new FuSa.Location(".github/workflows/"))
                    .category(FuSa.Category.config)
                    .remediation("add CI configuration to automate safety evidence generation")
                    .build());
        }
    }
}
