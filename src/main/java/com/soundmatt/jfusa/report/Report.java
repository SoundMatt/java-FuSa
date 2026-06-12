package com.soundmatt.jfusa.report;

import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.FuSa.Severity;
import com.soundmatt.jfusa.engine.Engine.Result;

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
        Result result
) {
    /** Formats this report as text, JSON, HTML, or SARIF. */
    public String render(String format) {
        return switch (format.toLowerCase()) {
            case "json"  -> JsonRenderer.render(this);
            case "html"  -> HtmlRenderer.render(this);
            case "sarif" -> SarifRenderer.render(this);
            default      -> TextRenderer.render(this);
        };
    }

    public List<Finding> errors()   {
        return result().findings().stream().filter(f -> f.severity() == Severity.ERROR).toList();
    }
    public List<Finding> warnings() {
        return result().findings().stream().filter(f -> f.severity() == Severity.WARNING).toList();
    }
    public List<Finding> infos()    {
        return result().findings().stream().filter(f -> f.severity() == Severity.INFO).toList();
    }

    /** Brief summary line (e.g. "3 error(s), 2 warning(s), 0 info(s)"). */
    public String summary() {
        long e = errors().size(), w = warnings().size(), i = infos().size();
        return e + " error(s), " + w + " warning(s), " + i + " info(s)";
    }

    /** Category breakdown map (category-name → count). */
    public Map<String, Long> categoryBreakdown() {
        return result().findings().stream()
                .collect(Collectors.groupingBy(f -> f.category().toString(), Collectors.counting()));
    }
}
