package com.soundmatt.jfusa;

import com.soundmatt.jfusa.coverage.Coverage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Coverage — structural coverage (JaCoCo) and MC/DC (LLVM export).
 */
class CoverageTest {

    @TempDir Path tmp;

    // ── Feature 3: MC/DC Coverage ─────────────────────────────────────────────

    @Test
    //fusa:test REQ-MCDC001
    void coverage_parseMcdc_returnsEmptyReportWhenNoFile() throws Exception {
        Coverage.McdcReport report = Coverage.parseMcdc(tmp.resolve("nonexistent.json"));
        assertEquals(0, report.totalFunctions());
        assertTrue(report.gatePass(), "empty file should pass gate");
    }

    @Test
    //fusa:test REQ-MCDC001
    void coverage_parseMcdc_parsesConditions() throws Exception {
        Path mcdcFile = tmp.resolve("mcdc.json");
        Files.writeString(mcdcFile, """
                {
                  "mcdc_records": [
                    {
                      "function": "foo",
                      "conditions": [
                        {"covered_true_count": 3, "covered_false_count": 2},
                        {"covered_true_count": 1, "covered_false_count": 1}
                      ]
                    }
                  ]
                }
                """);
        Coverage.McdcReport report = Coverage.parseMcdc(mcdcFile);
        assertEquals(1, report.totalFunctions());
        assertEquals(1, report.passingFunctions());
        assertTrue(report.gatePass());
        assertTrue(report.failingFunctions().isEmpty());
    }

    @Test
    //fusa:test REQ-MCDC001
    void coverage_parseMcdc_failsWhenConditionNotCovered() throws Exception {
        Path mcdcFile = tmp.resolve("mcdc.json");
        Files.writeString(mcdcFile, """
                {
                  "mcdc_records": [
                    {
                      "function": "bar",
                      "conditions": [
                        {"covered_true_count": 0, "covered_false_count": 2}
                      ]
                    }
                  ]
                }
                """);
        Coverage.McdcReport report = Coverage.parseMcdc(mcdcFile);
        assertEquals(1, report.totalFunctions());
        assertEquals(0, report.passingFunctions());
        assertFalse(report.gatePass(), "should fail gate when true count is 0");
        assertTrue(report.failingFunctions().contains("bar"));
    }

    @Test
    //fusa:test REQ-MCDC001
    void coverage_mcdcCondition_coveredWhenBothCountsPositive() {
        Coverage.McdcCondition cond = new Coverage.McdcCondition(1, 1);
        assertTrue(cond.isCovered());
    }

    @Test
    //fusa:test REQ-MCDC001
    void coverage_mcdcCondition_notCoveredWhenFalseCountZero() {
        Coverage.McdcCondition cond = new Coverage.McdcCondition(3, 0);
        assertFalse(cond.isCovered());
    }

    @Test
    //fusa:test REQ-MCDC001
    void coverage_mcdcCondition_notCoveredWhenTrueCountZero() {
        Coverage.McdcCondition cond = new Coverage.McdcCondition(0, 5);
        assertFalse(cond.isCovered());
    }

    @Test
    //fusa:test REQ-MCDC001
    void coverage_parseMcdc_multipleFunctions_partialPass() throws Exception {
        Path mcdcFile = tmp.resolve("mcdc.json");
        Files.writeString(mcdcFile, """
                {
                  "mcdc_records": [
                    {
                      "function": "good",
                      "conditions": [
                        {"covered_true_count": 2, "covered_false_count": 1}
                      ]
                    },
                    {
                      "function": "bad",
                      "conditions": [
                        {"covered_true_count": 0, "covered_false_count": 3}
                      ]
                    }
                  ]
                }
                """);
        Coverage.McdcReport report = Coverage.parseMcdc(mcdcFile);
        assertEquals(2, report.totalFunctions());
        assertEquals(1, report.passingFunctions());
        assertFalse(report.gatePass());
        assertTrue(report.failingFunctions().contains("bad"));
        assertFalse(report.failingFunctions().contains("good"));
    }

    @Test
    //fusa:test REQ-MCDC001
    void coverage_mcdcFunctionRecord_allCovered() {
        Coverage.McdcFunctionRecord fn = new Coverage.McdcFunctionRecord("fn", java.util.List.of(
                new Coverage.McdcCondition(1, 1),
                new Coverage.McdcCondition(2, 3)));
        assertTrue(fn.allCovered());
        assertEquals(0, fn.uncoveredCount());
    }

    @Test
    //fusa:test REQ-MCDC001
    void coverage_mcdcFunctionRecord_uncoveredCountCorrect() {
        Coverage.McdcFunctionRecord fn = new Coverage.McdcFunctionRecord("fn", java.util.List.of(
                new Coverage.McdcCondition(1, 1),
                new Coverage.McdcCondition(0, 1),
                new Coverage.McdcCondition(1, 0)));
        assertFalse(fn.allCovered());
        assertEquals(2, fn.uncoveredCount());
    }
}
