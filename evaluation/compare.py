"""
Naive-baseline vs hardened-scan comparison — the RQ3 core measurement.

Compares two triage_output.json files: one from a naive-baseline scan
(--naive-baseline flag in the scanning module) and one from the normal
hardened scan. This is what actually demonstrates (or fails to
demonstrate) LLM triage's false-positive-reduction value — the whole
point of RQ3.
"""

from __future__ import annotations


def compare_naive_vs_hardened(naive_triage: dict, hardened_triage: dict) -> dict:
    naive_verdicts = naive_triage.get("verdicts", [])
    hardened_verdicts = hardened_triage.get("verdicts", [])

    naive_fp = sum(1 for v in naive_verdicts if v["verdict"] == "false_positive")
    naive_tp = sum(1 for v in naive_verdicts if v["verdict"] == "true_positive")
    hardened_fp = sum(1 for v in hardened_verdicts if v["verdict"] == "false_positive")
    hardened_tp = sum(1 for v in hardened_verdicts if v["verdict"] == "true_positive")

    naive_total = len(naive_verdicts)
    hardened_total = len(hardened_verdicts)

    return {
        "naive_baseline": {
            "total_findings_from_scanner": naive_total,
            "llm_verdict_true_positive": naive_tp,
            "llm_verdict_false_positive": naive_fp,
            "llm_verdict_false_positive_rate": round(naive_fp / naive_total, 3) if naive_total else None,
        },
        "hardened_scan": {
            "total_findings_from_scanner": hardened_total,
            "llm_verdict_true_positive": hardened_tp,
            "llm_verdict_false_positive": hardened_fp,
            "llm_verdict_false_positive_rate": round(hardened_fp / hardened_total, 3) if hardened_total else None,
        },
        "interpretation": (
            "naive_baseline shows what the scanner's raw output looks like BEFORE the "
            "differential/block-page detector hardening AND before LLM triage — this is the "
            "'typical simple DAST tool' comparison point. The llm_verdict_false_positive count "
            "within naive_baseline shows how many of those raw findings the LLM correctly "
            "identified as noise on its own, even from unhardened scanner output. Compare "
            "hardened_scan's numbers to show the combined effect of both detector hardening "
            "and LLM triage together."
        ),
    }