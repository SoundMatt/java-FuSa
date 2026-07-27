package com.soundmatt.jfusa.report;

import com.soundmatt.jfusa.FuSa;
import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.config.Config;
import com.soundmatt.jfusa.engine.Engine.Result;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Report aggregate — collected findings plus run metadata. */
public record Report(
        String toolName,
        String toolVersion,
        String specVersion,
        String projectName,
        String standard,
        long timestampEpochMs,
        Result result,
        String projectRoot   // §3.2 MUST — absolute path of the --dir root
) {
    /** Convenience constructor — projectRoot set to empty when root is unknown. */
    public Report(Result result, Config cfg) {
        this(result, cfg, null);
    }

    /** Preferred constructor — includes projectRoot for §3.2 compliance. */
    public Report(Result result, Config cfg, Path root) {
        this("java-FuSa", FuSa.VERSION, FuSa.SPEC_VERSION,
                cfg != null ? cfg.project().name() : "",
                cfg != null ? cfg.project().standard().name() : "generic",
                System.currentTimeMillis(),
                result,
                root != null ? root.toAbsolutePath().toString() : "");
    }

    /** Formats this report as text, JSON, HTML, or SARIF. */
    //fusa:req REQ-REPORT001
    public String render(String format) {
        return switch (format.toLowerCase()) {
            case "json"  -> JsonRenderer.render(this);
            case "html"  -> HtmlRenderer.render(this);
            case "sarif" -> SarifRenderer.render(this);
            default      -> TextRenderer.render(this);
        };
    }

    //fusa:req REQ-REPORT002
    public List<Finding> errors()   {
        return result().findings().stream().filter(f -> f.severity() == Severity.ERROR).toList();
    }
    //fusa:req REQ-REPORT002
    public List<Finding> warnings() {
        return result().findings().stream().filter(f -> f.severity() == Severity.WARNING).toList();
    }
    //fusa:req REQ-REPORT002
    public List<Finding> infos()    {
        return result().findings().stream().filter(f -> f.severity() == Severity.INFO).toList();
    }

    /** Brief summary line (e.g. "3 error(s), 2 warning(s), 0 info(s)"). */
    //fusa:req REQ-REPORT003
    public String summary() {
        long e = errors().size(), w = warnings().size(), i = infos().size();
        return e + " error(s), " + w + " warning(s), " + i + " info(s)";
    }

    /** Category breakdown map (category-name → count). */
    //fusa:req REQ-REPORT004
    public Map<String, Long> categoryBreakdown() {
        return result().findings().stream()
                .collect(Collectors.groupingBy(f -> f.category().toString(), Collectors.counting()));
    }
}
