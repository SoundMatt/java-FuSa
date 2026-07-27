package com.soundmatt.jfusa.badge;

import com.soundmatt.jfusa.engine.Engine.Result;
import com.soundmatt.jfusa.report.Report;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** SVG badge generator — Shields.io-style status badge from check results. */
public final class Badge {

    private Badge() {}

    //fusa:req REQ-BADGE001
    public static String generate(Report report) {
        boolean pass = !report.result().hasErrors();
        String label = "java-FuSa";
        String status = pass ? "passing" : "failing";
        String color  = pass ? "#22c55e" : "#ef4444";
        int errors   = report.errors().size();
        int warnings = report.warnings().size();
        String message = pass
                ? (warnings > 0 ? warnings + " warning" + (warnings > 1 ? "s" : "") : "passing")
                : errors + " error" + (errors > 1 ? "s" : "");

        int labelW  = label.length() * 7 + 10;
        int statusW = message.length() * 7 + 10;
        int totalW  = labelW + statusW;

        return String.format("""
                <svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20">
                  <linearGradient id="s" x2="0" y2="100%%">
                    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
                    <stop offset="1" stop-opacity=".1"/>
                  </linearGradient>
                  <clipPath id="r">
                    <rect width="%d" height="20" rx="3" fill="#fff"/>
                  </clipPath>
                  <g clip-path="url(#r)">
                    <rect width="%d" height="20" fill="#555"/>
                    <rect x="%d" width="%d" height="20" fill="%s"/>
                    <rect width="%d" height="20" fill="url(#s)"/>
                  </g>
                  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
                    <text x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="%d">%s</text>
                    <text x="%d" y="140" transform="scale(.1)" textLength="%d">%s</text>
                    <text x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="%d">%s</text>
                    <text x="%d" y="140" transform="scale(.1)" textLength="%d">%s</text>
                  </g>
                </svg>
                """,
                totalW, totalW, labelW, labelW, statusW, color, totalW,
                labelW * 5, (label.length() * 60), label,
                labelW * 5, (label.length() * 60), label,
                (labelW + statusW / 2) * 10, (message.length() * 60), message,
                (labelW + statusW / 2) * 10, (message.length() * 60), message);
    }

    //fusa:req REQ-BADGE001
    public static void writeToFile(Path root, Report report, String outputName) throws IOException {
        String svg = generate(report);
        Path out = outputName != null ? root.resolve(outputName) : root.resolve("fusa-badge.svg");
        Files.writeString(out, svg);
    }
}
