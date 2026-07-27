package com.soundmatt.jfusa.vuln;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.engine.Rule;
import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dependency vulnerability scanner — parses pom.xml dependencies and checks known CVEs.
 * Writes vuln.json.
 */
public final class Vuln {

    public static final String VULN_JSON = "vuln.json";

    private static final Pattern DEP_BLOCK = Pattern.compile(
            "<dependency>.*?</dependency>", Pattern.DOTALL);
    private static final Pattern GROUP_ID    = Pattern.compile("<groupId>([^<]+)</groupId>");
    private static final Pattern ARTIFACT_ID = Pattern.compile("<artifactId>([^<]+)</artifactId>");
    private static final Pattern VERSION_TAG = Pattern.compile("<version>([^<]+)</version>");

    static {
        Engine.DEFAULT.mustRegister(new RuleVulnReportPresent());
    }

    private Vuln() {}
    public static void activate() {}

    //fusa:req REQ-VULN001
    public record Dependency(String groupId, String artifactId, String version) {}
    //fusa:req REQ-VULN001
    public record VulnEntry(Dependency dep, String cveId, String severity, String description) {}

    //fusa:req REQ-VULN002
    public static List<Dependency> parsePom(Path root) throws IOException {
        Path pom = root.resolve("pom.xml");
        if (!Files.exists(pom)) return List.of();
        String content = Files.readString(pom);
        List<Dependency> deps = new ArrayList<>();
        Matcher blocks = DEP_BLOCK.matcher(content);
        while (blocks.find()) {
            String block = blocks.group();
            Matcher g = GROUP_ID.matcher(block);
            Matcher a = ARTIFACT_ID.matcher(block);
            Matcher v = VERSION_TAG.matcher(block);
            if (g.find() && a.find()) {
                deps.add(new Dependency(g.group(1), a.group(1), v.find() ? v.group(1) : "unknown"));
            }
        }
        return deps;
    }

    //fusa:req REQ-VULN003
    public static void scan(Path root) throws IOException {
        List<Dependency> deps = parsePom(root);
        // Offline scan against a minimal known-bad list
        List<VulnEntry> vulns = checkKnownVulns(deps);
        writeReport(root, deps, vulns);
        if (vulns.isEmpty()) {
            System.out.println("No known vulnerabilities found in " + deps.size() + " dependencies.");
        } else {
            System.out.println(vulns.size() + " vulnerability finding(s) in " + deps.size() + " dependencies.");
        }
    }

    //fusa:req REQ-VULN004
    public static List<VulnEntry> checkKnownVulns(List<Dependency> deps) {
        Map<String, String> knownBad = Map.of(
            "log4j-core:2.14", "CVE-2021-44228:CRITICAL:Log4Shell — RCE via JNDI lookup in log messages",
            "log4j-core:2.15", "CVE-2021-45046:CRITICAL:Log4Shell bypass in 2.15.0",
            "spring-webmvc:5.3.17", "CVE-2022-22965:CRITICAL:Spring4Shell — RCE via data binding",
            "commons-text:1.9", "CVE-2022-42889:CRITICAL:Text4Shell — RCE via script interpolation"
        );
        List<VulnEntry> found = new ArrayList<>();
        for (Dependency d : deps) {
            String key = d.artifactId() + ":" + d.version();
            if (knownBad.containsKey(key)) {
                String[] parts = knownBad.get(key).split(":");
                found.add(new VulnEntry(d, parts[0], parts[1], parts[2]));
            }
        }
        return found;
    }

    static void writeReport(Path root, List<Dependency> deps, List<VulnEntry> vulns) throws IOException {
        var w = new Json.Writer();
        w.objectStart();
        w.field("schemaVersion", FuSa.SPEC_VERSION);
        w.field("kind", "vuln-report");
        w.field("tool", "java-FuSa");
        w.field("toolVersion", FuSa.VERSION);
        w.field("language", "java");
        w.field("generatedAt", Instant.now().toString());
        w.field("dependencyCount", deps.size());
        w.field("vulnerabilityCount", vulns.size());
        w.key("vulnerabilities"); w.arrayStart();
        for (VulnEntry v : vulns) {
            w.objectStart();
            w.field("groupId", v.dep().groupId());
            w.field("artifactId", v.dep().artifactId());
            w.field("version", v.dep().version());
            w.field("cveId", v.cveId());
            w.field("severity", v.severity());
            w.field("description", v.description());
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(VULN_JSON), w.toPretty() + "\n");
    }

    static final class RuleVulnReportPresent implements Rule {
        public String id() { return "VULN001"; }
        public String description() { return "Vulnerability scan report (vuln.json) should be present."; }

        //fusa:req REQ-VULN005
        public List<Finding> run(Path root, Config cfg) {
            if (!Files.exists(root.resolve(VULN_JSON))) {
                return List.of(Finding.builder("VULN001", Severity.INFO,
                        "no vuln.json — run 'jfusa vuln' to scan dependencies",
                        new FuSa.Location(VULN_JSON))
                        .category(FuSa.Category.SUPPLY_CHAIN)
                        .standard("ISO 21434").clause("8")
                        .remediation("run 'jfusa vuln' to scan pom.xml dependencies for known CVEs")
                        .build());
            }
            return List.of();
        }
    }
}
