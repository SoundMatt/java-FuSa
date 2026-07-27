package com.soundmatt.jfusa.report;

import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;

import java.time.Instant;

/** HTML compliance report renderer with inline CSS. */
public final class HtmlRenderer {

    private HtmlRenderer() {}

    //fusa:req REQ-REPORT005
    public static String render(Report r) {
        var sb = new StringBuilder();
        sb.append("""
                <!DOCTYPE html>
                <html lang="en">
                <head><meta charset="UTF-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>java-FuSa Safety Report</title>
                <style>
                  body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
                  h1{border-bottom:3px solid #2563eb;padding-bottom:.5rem}
                  .meta{background:#f1f5f9;padding:1rem;border-radius:.5rem;margin-bottom:1.5rem}
                  .meta table{border-collapse:collapse;width:100%}
                  .meta td{padding:.25rem .5rem}
                  .meta td:first-child{font-weight:600;width:120px}
                  .finding{border-left:4px solid #e5e7eb;padding:.75rem 1rem;margin:.5rem 0;border-radius:0 .5rem .5rem 0}
                  .finding.error{border-color:#ef4444;background:#fef2f2}
                  .finding.warning{border-color:#f59e0b;background:#fffbeb}
                  .finding.info{border-color:#3b82f6;background:#eff6ff}
                  .badge{display:inline-block;padding:.1rem .4rem;border-radius:.25rem;font-size:.75rem;font-weight:700;text-transform:uppercase}
                  .badge.error{background:#ef4444;color:#fff}
                  .badge.warning{background:#f59e0b;color:#fff}
                  .badge.info{background:#3b82f6;color:#fff}
                  .loc{color:#6b7280;font-size:.85rem;margin:.25rem 0}
                  .rem{color:#374151;font-size:.875rem;margin-top:.25rem}
                  .pass{color:#22c55e;font-weight:700}
                  .fail{color:#ef4444;font-weight:700}
                  .summary{background:#f8fafc;padding:1rem;border-radius:.5rem;margin-top:1.5rem}
                </style>
                </head>
                <body>
                """);
        sb.append("<h1>java-FuSa Safety Report</h1>\n");
        sb.append("<div class='meta'><table>\n");
        sb.append(tr("Tool", r.toolName() + " v" + r.toolVersion()));
        sb.append(tr("Spec", "x-FuSa " + r.specVersion()));
        sb.append(tr("Project", r.projectName()));
        sb.append(tr("Standard", r.standard()));
        sb.append(tr("Date", Instant.ofEpochMilli(r.timestampEpochMs()).toString()));
        sb.append("</table></div>\n");

        if (r.result().findings().isEmpty()) {
            sb.append("<p class='pass'>✓ No findings.</p>\n");
        } else {
            sb.append("<h2>Findings</h2>\n");
            for (Finding f : r.result().findings()) {
                String cls = f.severity().name().toLowerCase();
                sb.append("<div class='finding ").append(cls).append("'>\n");
                sb.append("<span class='badge ").append(cls).append("'>").append(f.severity()).append("</span> ");
                sb.append("<strong>").append(esc(f.ruleId())).append("</strong> — ").append(esc(f.message())).append("\n");
                sb.append("<div class='loc'>").append(esc(f.location().file()));
                if (f.location().line() > 0) sb.append(':').append(f.location().line());
                sb.append("</div>\n");
                if (!f.remediation().isBlank()) {
                    sb.append("<div class='rem'>💡 ").append(esc(f.remediation())).append("</div>\n");
                }
                sb.append("</div>\n");
            }
        }

        boolean pass = !r.result().hasErrors();
        sb.append("<div class='summary'><strong>Summary:</strong> ").append(r.summary());
        sb.append(" — Status: <span class='").append(pass ? "pass" : "fail").append("'>")
                .append(pass ? "PASS" : "FAIL").append("</span></div>\n");
        sb.append("</body></html>\n");
        return sb.toString();
    }

    private static String tr(String k, String v) {
        return "<tr><td>" + esc(k) + "</td><td>" + esc(v) + "</td></tr>\n";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
