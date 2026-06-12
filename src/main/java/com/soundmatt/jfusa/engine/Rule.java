package com.soundmatt.jfusa.engine;

import com.soundmatt.jfusa.FuSa.Finding;
import com.soundmatt.jfusa.config.Config;

import java.nio.file.Path;
import java.util.List;

/**
 * Interface implemented by every java-FuSa safety check.
 */
public interface Rule {

    /** Unique rule identifier (e.g. "FUSA001"). */
    String id();

    /** Short human-readable summary of the rule. */
    String description();

    /**
     * Executes the rule against {@code projectRoot} and returns any findings.
     * An error should be signalled by throwing a checked or unchecked exception;
     * it does not imply findings exist.
     */
    List<Finding> run(Path projectRoot, Config cfg) throws Exception;
}
