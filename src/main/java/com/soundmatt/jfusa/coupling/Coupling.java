package com.soundmatt.jfusa.coupling;

import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Data/control coupling detection — coupling-report.json (DO-178C MC/DC requirement).
 */
public final class Coupling {

    public static final String COUPLING_JSON = "coupling-report.json";

    private static final Pattern METHOD_CALL = Pattern.compile(
            "(\\w+)\\s*\\.\\s*(\\w+)\\s*\\(");
    private static final Pattern PARAM_PASS = Pattern.compile(
            "\\b(\\w+)\\s*=\\s*[^;]+\\.\\s*(\\w+)\\s*\\(");

    private Coupling() {}

    public record CouplingEntry(String from, String to, String type, int line) {}

    public static List<CouplingEntry> analyze(Path root) throws IOException {
        List<CouplingEntry> couplings = new ArrayList<>();
        List<Path> javaFiles = findJavaFiles(root);
        for (Path f : javaFiles) {
            String rel = root.relativize(f).toString();
            List<String> lines = Files.readAllLines(f);
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                Matcher m = METHOD_CALL.matcher(line);
                while (m.find()) {
                    String target = m.group(1) + "." + m.group(2);
                    couplings.add(new CouplingEntry(rel, target, "control", i + 1));
                }
                Matcher d = PARAM_PASS.matcher(line);
                while (d.find()) {
                    couplings.add(new CouplingEntry(rel, d.group(2), "data", i + 1));
                }
            }
        }
        return couplings;
    }

    public static void generate(Path root) throws IOException {
        List<CouplingEntry> couplings = analyze(root);
        var w = new Json.Writer();
        w.objectStart();
        w.field("schema", "x-fusa-coupling-1.0");
        w.field("standard", "DO-178C §6.3.4b MC/DC");
        w.field("timestamp", Instant.now().toString());
        w.field("totalCouplings", couplings.size());
        long dataCoupling = couplings.stream().filter(c -> "data".equals(c.type())).count();
        long controlCoupling = couplings.stream().filter(c -> "control".equals(c.type())).count();
        w.field("dataCouplings", dataCoupling);
        w.field("controlCouplings", controlCoupling);
        w.key("entries"); w.arrayStart();
        for (CouplingEntry c : couplings.subList(0, Math.min(100, couplings.size()))) {
            w.objectStart();
            w.field("from", c.from());
            w.field("to", c.to());
            w.field("type", c.type());
            w.field("line", c.line());
            w.objectEnd();
        }
        w.arrayEnd();
        w.objectEnd();
        Files.writeString(root.resolve(COUPLING_JSON), w.toPretty() + "\n");
        System.out.printf("Coupling report: %d data, %d control couplings%n", dataCoupling, controlCoupling);
    }

    static List<Path> findJavaFiles(Path root) throws IOException {
        Path src = root.resolve("src/main/java");
        if (!Files.exists(src)) return List.of();
        try (Stream<Path> s = Files.walk(src)) {
            return s.filter(p -> p.toString().endsWith(".java")).toList();
        }
    }
}
