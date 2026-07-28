package com.soundmatt.jfusa.attestation;

import com.soundmatt.jfusa.internal.CanonJson;
import com.soundmatt.jfusa.internal.Json;

import java.util.Map;

/**
 * x-FuSa spec §1.6.2 attestation object — a DCO-style independent-review
 * assertion carried inside an evidence artifact ({@code fmea.json},
 * {@code .fusa-hara.json}, {@code tara.json}, {@code safety-case.json},
 * {@code sas.json}) that suppresses a FUSA-STUB002 (Rule B) finding once it is
 * genuine (independent reviewer) and non-stale (content hash still matches).
 *
 * <p>The tool never fabricates or edits this block itself — a human (or a
 * review process) adds it to the generated JSON after inspecting the content;
 * the relevant artifact command must then carry it forward verbatim across
 * regenerations rather than discarding it (see each artifact's {@code load}
 * or generation path).
 */
public final class Attestation {

    /** Absent/unrecognised status MUST be treated as {@code "heuristic"} (fail-safe). */
    public static final String HEURISTIC = "heuristic";
    public static final String REVIEWED = "reviewed";

    private final String status;
    private final String implementationAuthor;
    private final String independentReviewer;
    private final String reviewedAt;
    private final String contentHash;

    //fusa:req REQ-ATT001
    public Attestation(String status, String implementationAuthor, String independentReviewer,
                        String reviewedAt, String contentHash) {
        this.status = REVIEWED.equals(status) ? REVIEWED : HEURISTIC;
        this.implementationAuthor = implementationAuthor == null ? "" : implementationAuthor;
        this.independentReviewer = independentReviewer == null ? "" : independentReviewer;
        this.reviewedAt = reviewedAt == null ? "" : reviewedAt;
        this.contentHash = contentHash == null ? "" : contentHash;
    }

    public String status() { return status; }
    public String implementationAuthor() { return implementationAuthor; }
    public String independentReviewer() { return independentReviewer; }
    public String reviewedAt() { return reviewedAt; }
    public String contentHash() { return contentHash; }

    //fusa:req REQ-ATT001
    public boolean isReviewed() { return REVIEWED.equals(status); }

    /** Independence (MUST when {@code status="reviewed"}): reviewer must differ from author. */
    //fusa:req REQ-ATT002
    public boolean isIndependent() {
        return isReviewed()
                && !independentReviewer.isBlank()
                && !independentReviewer.equalsIgnoreCase(implementationAuthor);
    }

    /**
     * Recomputes the RFC 8785 content hash over {@code substantiveContent} (the
     * artifact's entries/hazards/nodes collection — excluding the attestation
     * object itself and {@code generatedAt}, per §1.6.2) and compares it against
     * the stored {@code contentHash}. A mismatch means the artifact changed
     * since review: the attestation MUST be treated as stale (fall back to
     * {@code "heuristic"}).
     */
    //fusa:req REQ-ATT003
    public boolean isFresh(Object substantiveContent) {
        if (!isReviewed() || contentHash.isBlank()) return false;
        return contentHash.equals(CanonJson.sha256Prefixed(substantiveContent));
    }

    /** True only when this is a genuine, non-stale independent review — the sole condition
     *  under which a FUSA-STUB002 (Rule B) finding MUST be suppressed (§1.6.2). */
    //fusa:req REQ-ATT004
    public boolean suppressesRuleB(Object substantiveContent) {
        return isIndependent() && isFresh(substantiveContent);
    }

    /** Parses an {@code "attestation"} object from a decoded document; {@code null} when absent. */
    //fusa:req REQ-ATT005
    public static Attestation fromJson(Map<String, Object> doc) {
        if (doc == null) return null;
        Object raw = doc.get("attestation");
        if (!(raw instanceof Map<?, ?> m) || m.isEmpty()) return null;
        @SuppressWarnings("unchecked") Map<String, Object> att = (Map<String, Object>) m;
        return new Attestation(
                Json.str(att, "status", HEURISTIC),
                Json.str(att, "implementationAuthor", ""),
                Json.str(att, "independentReviewer", ""),
                Json.str(att, "reviewedAt", ""),
                Json.str(att, "contentHash", ""));
    }

    /** Writes this attestation, verbatim, as the document-level {@code "attestation"} member. */
    //fusa:req REQ-ATT005
    public void writeJson(Json.Writer w) {
        w.key("attestation");
        w.objectStart();
        w.field("status", status);
        w.fieldIfNonBlank("implementationAuthor", implementationAuthor);
        w.fieldIfNonBlank("independentReviewer", independentReviewer);
        w.fieldIfNonBlank("reviewedAt", reviewedAt);
        w.fieldIfNonBlank("contentHash", contentHash);
        w.objectEnd();
    }
}
