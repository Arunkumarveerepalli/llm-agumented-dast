"""
Evaluation module entry point.

Computes the proposal's exact RQ3 measurement: mean completeness score
(out of 5, per the named rubric criteria) for LLM-generated reports vs
raw scanner alerts, from the SAME scan_output.json — so both sides of
the comparison come from the same set of findings.

Usage:
    python run_eval.py --triage-input ../llm_triage/triage_output.json \
        --scan-input ../scanning/scan_output.json \
        --output eval_output.json --verbose

Usage (with naive-baseline RQ3 false-positive comparison too):
    python run_eval.py --triage-input ../llm_triage/triage_output.json \
        --scan-input ../scanning/scan_output.json \
        --naive-triage-input ../llm_triage/triage_output_raw.json \
        --output eval_output.json --verbose
"""

from __future__ import annotations

import argparse
import json
import sys

from rubric import score_llm_report, score_raw_alert
from models import EvalResult
from compare import compare_naive_vs_hardened


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluation module — RQ3 completeness rubric (LLM reports vs raw alerts).")
    parser.add_argument("--triage-input", required=True, help="Path to triage_output.json (hardened scan)")
    parser.add_argument("--scan-input", required=True, help="Path to the matching scan_output.json")
    parser.add_argument("--naive-triage-input", default=None, help="Optional: triage_output_raw.json from a --naive-baseline scan, for the RQ1 false-positive comparison")
    parser.add_argument("--output", default="eval_output.json")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    args = parse_args()

    print(f"[*] Loading triage results from {args.triage_input}...")
    try:
        triage_data = load_json(args.triage_input)
        scan_data = load_json(args.scan_input)
    except FileNotFoundError as exc:
        print(f"[!] File not found: {exc.filename}", file=sys.stderr)
        return 1

    findings_by_id = {f["id"]: f for f in scan_data.get("findings", [])}
    result = EvalResult(target=triage_data.get("target", "unknown"))

    print(f"[*] Scoring {len(triage_data.get('verdicts', []))} LLM reports against the 5-criteria rubric...")
    for verdict in triage_data.get("verdicts", []):
        finding = findings_by_id.get(verdict["finding_id"])
        if finding is None:
            print(f"[!] Warning: verdict {verdict['finding_id']} has no matching finding — skipping", file=sys.stderr)
            continue
        result.add_llm_score(score_llm_report(verdict, finding))

    print(f"[*] Scoring {len(scan_data.get('findings', []))} raw scanner alerts against the same rubric...")
    for finding in scan_data.get("findings", []):
        result.add_raw_score(score_raw_alert(finding))

    if args.naive_triage_input:
        print(f"[*] Loading naive-baseline triage from {args.naive_triage_input} for RQ1 comparison...")
        try:
            naive_triage_data = load_json(args.naive_triage_input)
            result.naive_comparison = compare_naive_vs_hardened(naive_triage_data, triage_data)
        except FileNotFoundError as exc:
            print(f"[!] Naive triage file not found: {exc.filename} — skipping", file=sys.stderr)

    result.save(args.output)
    print(f"[+] Evaluation complete: written to {args.output}")

    summary = result.summary()
    print()
    print(f"    RQ3 — Report completeness (out of 5):")
    print(f"      LLM-generated reports: {summary['llm_report_mean_completeness']} (n={summary['llm_report_count']})")
    print(f"      Raw scanner alerts:    {summary['raw_alert_mean_completeness']} (n={summary['raw_alert_count']})")
    print(f"      {summary['rq3_result']}")

    if result.naive_comparison:
        nc = result.naive_comparison
        print()
        print("    RQ1 — False-positive comparison (naive baseline vs hardened):")
        print(f"      Naive:    {nc['naive_baseline']['llm_verdict_false_positive']}/{nc['naive_baseline']['total_findings_from_scanner']} findings judged false_positive")
        print(f"      Hardened: {nc['hardened_scan']['llm_verdict_false_positive']}/{nc['hardened_scan']['total_findings_from_scanner']} findings judged false_positive")

    return 0


if __name__ == "__main__":
    sys.exit(main())