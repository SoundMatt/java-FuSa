package com.soundmatt.jfusa.report;

import com.soundmatt.jfusa.FuSa.Finding;

import java.time.Instant;
import java.util.List;

/** Plain-text compliance report renderer. */
public final class TextRenderer {

    private TextRenderer() {}

    public static String render(Report r) {
        boolean noColor = System.getenv("NO_COLOR") != null || System.getProperty("jfusa.nocolor") != null;
        StringBuilder sb = new StringBuilder();
        sb.append("java-FuSa Safety Report\n");
        sb.append("=".repeat(60)).append('\n');
        sb.append("Tool    : ").append(r.toolName()).append(" v").append(r.toolVersion()).append('\n');
        sb.append("Spec    : x-FuSa ").append(r.specVersion()).append('\n');
        sb.append("Project : ").append(r.projectName()).append('\n');
        sb.append("Standard: ").append(r.standard()).append('\n');
        sb.append("Date    : ").append(Instant.ofEpochMilli(r.timestampEpochMs())).append('\n');
        sb.append("-".repeat(60)).append('\n');

        List<Finding> findings = r.result().findings();
        if (findings.isEmpty()) {
            sb.append("✓ No findings.\n");
        } else {
            for (Finding f : findings) {
                String prefix = switch (f.severity()) {
                    case ERROR   -> noColor ? "[ERROR]   " : "\033[31m[ERROR]\033[0m   ";
                    case WARNING -> noColor ? "[WARNING] " : "\033[33m[WARNING]\033[0m ";
                    case INFO    -> noColor ? "[INFO]    " : "\033[36m[INFO]\033[0m    ";
                };
                sb.append(prefix);
                sb.append(f.ruleId()).append("  ");
                sb.append(f.location().file());
                if (f.location().line() > 0) sb.append(':').append(f.location().line());
                sb.append('\n');
                sb.append("         ").append(f.message()).append('\n');
                if (!f.remediation().isBlank()) {
                    sb.append("         Remediation: ").append(f.remediation()).append('\n');
                }
            }
        }

        if (!r.result().errors().isEmpty()) {
            sb.append("\nRule execution errors:\n");
            for (String e : r.result().errors()) sb.append("  ").append(e).append('\n');
        }

        sb.append("-".repeat(60)).append('\n');
        sb.append("Summary : ").append(r.summary()).append('\n');
        sb.append(r.result().hasErrors() ? "Status  : FAIL\n" : "Status  : PASS\n");
        return sb.toString();
    }
}
