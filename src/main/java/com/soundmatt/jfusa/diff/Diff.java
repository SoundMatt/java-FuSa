package com.soundmatt.jfusa.diff;

import com.soundmatt.jfusa.internal.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

/**
 * Report diff engine — compares two JSON check reports (introduced/resolved/unchanged).
 * Exits 1 if new findings were introduced (CI regression gate).
 */
public final class Diff {

    private Diff() {}

    public record DiffResult(
            List<String> introduced, List<String> resolved, List<String> unchanged) {
        //fusa:req REQ-DIFF001
        public boolean hasIntroduced() { return !introduced.isEmpty(); }
    }

    @SuppressWarnings("unchecked")
    //fusa:req REQ-DIFF001
    public static DiffResult compare(Path baselineReport, Path currentReport) throws IOException {
        Set<String> baselineFp = extractFingerprints(Files.readString(baselineReport));
        Set<String> currentFp  = extractFingerprints(Files.readString(currentReport));

        List<String> introduced = new ArrayList<>(currentFp);
        introduced.removeAll(baselineFp);

        List<String> resolved = new ArrayList<>(baselineFp);
        resolved.removeAll(currentFp);

        List<String> unchanged = new ArrayList<>(baselineFp);
        unchanged.retainAll(currentFp);

        return new DiffResult(
                Collections.unmodifiableList(introduced),
                Collections.unmodifiableList(resolved),
                Collections.unmodifiableList(unchanged));
    }

    @SuppressWarnings("unchecked")
    static Set<String> extractFingerprints(String json) {
        try {
            Map<String, Object> doc = Json.parseObject(json);
            Set<String> fps = new LinkedHashSet<>();
            for (Object f : Json.arr(doc, "findings")) {
                if (f instanceof Map<?,?> m) {
                    String fp = Json.str((Map<String, Object>) m, "fingerprint", "");
                    if (!fp.isBlank()) fps.add(fp);
                    else {
                        // Fallback: ruleId+file
                        String ruleId = Json.str((Map<String, Object>) m, "ruleId", "");
                        Map<String, Object> loc = Json.obj((Map<String, Object>) m, "location");
                        String file = Json.str(loc, "file", "");
                        fps.add(ruleId + ":" + file);
                    }
                }
            }
            return fps;
        } catch (Exception e) {
            return Set.of();
        }
    }

    //fusa:req REQ-DIFF001
    public static String renderText(DiffResult diff, String baseline, String current) {
        var sb = new StringBuilder();
        sb.append("Report Diff: ").append(baseline).append(" → ").append(current).append('\n');
        sb.append("=".repeat(60)).append('\n');
        sb.append("Introduced : ").append(diff.introduced().size()).append('\n');
        sb.append("Resolved   : ").append(diff.resolved().size()).append('\n');
        sb.append("Unchanged  : ").append(diff.unchanged().size()).append('\n');
        if (!diff.introduced().isEmpty()) {
            sb.append("\nINTRODUCED:\n");
            diff.introduced().forEach(fp -> sb.append("  + ").append(fp).append('\n'));
        }
        if (!diff.resolved().isEmpty()) {
            sb.append("\nRESOLVED:\n");
            diff.resolved().forEach(fp -> sb.append("  - ").append(fp).append('\n'));
        }
        sb.append('\n').append(diff.hasIntroduced() ? "Status: FAIL (new findings introduced)\n" : "Status: PASS\n");
        return sb.toString();
    }
}
