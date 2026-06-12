package com.soundmatt.jfusa;

import com.soundmatt.jfusa.vuln.Vuln;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class VulnTest {

    @TempDir Path tmp;

    @Test
    void parsePom_noFile_returnsEmpty() throws Exception {
        List<Vuln.Dependency> deps = Vuln.parsePom(tmp);
        assertTrue(deps.isEmpty());
    }

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

    @Test
    void checkKnownVulns_detectsLog4Shell() {
        List<Vuln.Dependency> deps = List.of(
                new Vuln.Dependency("org.apache.logging.log4j", "log4j-core", "2.14"));
        List<Vuln.VulnEntry> vulns = Vuln.checkKnownVulns(deps);
        assertFalse(vulns.isEmpty(), "Log4Shell should be detected");
        assertEquals("CVE-2021-44228", vulns.get(0).cveId());
        assertEquals("CRITICAL", vulns.get(0).severity());
    }

    @Test
    void checkKnownVulns_noHits_onSafeVersion() {
        List<Vuln.Dependency> deps = List.of(
                new Vuln.Dependency("org.apache.logging.log4j", "log4j-core", "2.17.2"));
        List<Vuln.VulnEntry> vulns = Vuln.checkKnownVulns(deps);
        assertTrue(vulns.isEmpty(), "No known vuln for patched version");
    }

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
}
