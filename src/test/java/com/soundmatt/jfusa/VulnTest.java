package com.soundmatt.jfusa;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine;
import com.soundmatt.jfusa.vuln.Vuln;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class VulnTest {

    @TempDir Path tmp;

    //fusa:test REQ-VULN002
    @Test
    void parsePom_noFile_returnsEmpty() throws Exception {
        List<Vuln.Dependency> deps = Vuln.parsePom(tmp);
        assertTrue(deps.isEmpty());
    }

    //fusa:test REQ-VULN001
    //fusa:test REQ-VULN002
    @Test
    void parsePom_extractsDependencies() throws Exception {
        Files.writeString(tmp.resolve("pom.xml"), """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>org.apache.logging.log4j</groupId>
                      <artifactId>log4j-core</artifactId>
                      <version>2.14</version>
                    </dependency>
                  </dependencies>
                </project>
                """);
        List<Vuln.Dependency> deps = Vuln.parsePom(tmp);
        assertFalse(deps.isEmpty());
        assertEquals("log4j-core", deps.get(0).artifactId());
        assertEquals("2.14", deps.get(0).version());
    }

    //fusa:test REQ-VULN001
    //fusa:test REQ-VULN004
    @Test
    void checkKnownVulns_detectsLog4Shell() {
        List<Vuln.Dependency> deps = List.of(
                new Vuln.Dependency("org.apache.logging.log4j", "log4j-core", "2.14"));
        List<Vuln.VulnEntry> vulns = Vuln.checkKnownVulns(deps);
        assertFalse(vulns.isEmpty(), "Log4Shell should be detected");
        assertEquals("CVE-2021-44228", vulns.get(0).cveId());
        assertEquals("CRITICAL", vulns.get(0).severity());
    }

    //fusa:test REQ-VULN004
    @Test
    void checkKnownVulns_noHits_onSafeVersion() {
        List<Vuln.Dependency> deps = List.of(
                new Vuln.Dependency("org.apache.logging.log4j", "log4j-core", "2.17.2"));
        List<Vuln.VulnEntry> vulns = Vuln.checkKnownVulns(deps);
        assertTrue(vulns.isEmpty(), "No known vuln for patched version");
    }

    //fusa:test REQ-VULN003
    @Test
    void scan_writesVulnReport() throws Exception {
        Files.writeString(tmp.resolve("pom.xml"), """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>g</groupId>
                      <artifactId>a</artifactId>
                      <version>1.0</version>
                    </dependency>
                  </dependencies>
                </project>
                """);
        Vuln.scan(tmp);
        assertTrue(Files.exists(tmp.resolve(Vuln.VULN_JSON)));
    }

    //fusa:test REQ-VULN005
    @Test
    void ruleVulnReportPresent_firesWhenMissing_silentWhenPresent() throws Exception {
        Vuln.activate();
        Config cfg = Config.defaultConfig("vuln-rule-test");
        Engine.Result before = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("VULN001"));
        assertTrue(before.findings().stream().anyMatch(f -> f.ruleId().equals("VULN001")),
                "VULN001 should fire when vuln.json is absent");

        Vuln.scan(tmp);
        Engine.Result after = Engine.DEFAULT.runFilter(tmp, cfg, r -> r.id().equals("VULN001"));
        assertTrue(after.findings().stream().noneMatch(f -> f.ruleId().equals("VULN001")),
                "VULN001 should be silent once vuln.json exists");
    }
}
