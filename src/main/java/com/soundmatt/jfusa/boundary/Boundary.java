package com.soundmatt.jfusa.boundary;

import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.lint.LintRules;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Component boundary diagrams — package dependency graph in Mermaid and DOT formats.
 */
public final class Boundary {

    public static final String BOUNDARY_MERMAID = "boundary.mermaid";
    public static final String BOUNDARY_DOT     = "boundary.dot";

    private static final Pattern IMPORT_STMT = Pattern.compile("^import\\s+([\\w.]+);");
    private static final Pattern PACKAGE_STMT = Pattern.compile("^package\\s+([\\w.]+);");

    private Boundary() {}

    //fusa:req REQ-BOUNDARY001
    public static Map<String, Set<String>> buildDependencyGraph(Path root, Config cfg) throws IOException {
        Map<String, Set<String>> graph = new LinkedHashMap<>();
        for (Path f : LintRules.javaFiles(root, cfg)) {
            List<String> lines = LintRules.readLines(f);
            String pkg = null;
            for (String line : lines) {
                Matcher m = PACKAGE_STMT.matcher(line.strip());
                if (m.find()) { pkg = m.group(1); break; }
            }
            if (pkg == null) continue;
            Set<String> deps = graph.computeIfAbsent(pkg, k -> new LinkedHashSet<>());
            for (String line : lines) {
                Matcher im = IMPORT_STMT.matcher(line.strip());
                if (im.find()) {
                    String imp = im.group(1);
                    String impPkg = imp.contains(".") ? imp.substring(0, imp.lastIndexOf('.')) : imp;
                    if (!impPkg.equals(pkg) && !impPkg.startsWith("java.") && !impPkg.startsWith("javax.")) {
                        deps.add(impPkg);
                    }
                }
            }
        }
        return graph;
    }

    //fusa:req REQ-BOUNDARY001
    public static void generate(Path root, Config cfg) throws IOException {
        Map<String, Set<String>> graph = buildDependencyGraph(root, cfg);
        writeMermaid(root, graph);
        writeDot(root, graph);
    }

    static void writeMermaid(Path root, Map<String, Set<String>> graph) throws IOException {
        var sb = new StringBuilder("graph TD\n");
        Map<String, String> ids = new LinkedHashMap<>();
        int i = 0;
        for (String pkg : graph.keySet()) ids.put(pkg, "P" + i++);
        for (var e : graph.entrySet()) {
            String srcId = ids.getOrDefault(e.getKey(), "P?");
            String label = e.getKey().contains(".") ? e.getKey().substring(e.getKey().lastIndexOf('.') + 1) : e.getKey();
            for (String dep : e.getValue()) {
                String dstId = ids.computeIfAbsent(dep, k -> "P" + ids.size());
                String dstLabel = dep.contains(".") ? dep.substring(dep.lastIndexOf('.') + 1) : dep;
                sb.append("    ").append(srcId).append("[\"").append(label).append("\"] --> ")
                  .append(dstId).append("[\"").append(dstLabel).append("\"]\n");
            }
        }
        Files.writeString(root.resolve(BOUNDARY_MERMAID), sb.toString());
    }

    static void writeDot(Path root, Map<String, Set<String>> graph) throws IOException {
        var sb = new StringBuilder("digraph boundary {\n  rankdir=LR;\n  node [shape=box];\n");
        for (var e : graph.entrySet()) {
            for (String dep : e.getValue()) {
                sb.append("  \"").append(e.getKey()).append("\" -> \"").append(dep).append("\";\n");
            }
        }
        sb.append("}\n");
        Files.writeString(root.resolve(BOUNDARY_DOT), sb.toString());
    }
}
