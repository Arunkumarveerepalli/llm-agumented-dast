"""
LLM triage module entry point.

Usage:
    python run_triage.py --scan-input ../scanning/scan_output.json \
        --model llama3.1:8b --output triage_output.json --verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from ollama_client import triage_finding
from models import TriageResult


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LLM triage — judges scanner findings using a local LLM.")
    parser.add_argument("--scan-input", required=True, help="Path to scan_output.json")
    parser.add_argument("--model", default="llama3.1:8b", help="Ollama model name")
    parser.add_argument("--output", default="triage_output.json")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    print(f"[*] Loading scan results from {args.scan_input}...")
    try:
        with open(args.scan_input, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Scan input file not found: {args.scan_input}", file=sys.stderr)
        return 1

    findings = scan_data.get("findings", [])
    if not findings:
        print("[!] No findings in scan output — nothing to triage.")
        return 0

    result = TriageResult(target=scan_data.get("target", "unknown"), model_used=args.model)

    print(f"[*] Triaging {len(findings)} findings with {args.model}...")
    for i, finding in enumerate(findings, 1):
        print(f"    [{i}/{len(findings)}] {finding['id']}: {finding['vuln_class']} on {finding['endpoint']}")
        try:
            verdict = triage_finding(finding, model=args.model)
            result.add(verdict)
        except RuntimeError as exc:
            print(f"    [!] Triage failed for {finding['id']}: {exc}", file=sys.stderr)
            result.add_error(finding["id"], str(exc))

    result.save(args.output)
    print(f"[+] Triage complete: {len(result.verdicts)} verdicts written to {args.output}")

    summary = result.summary()
    for verdict_type, count in summary["by_verdict"].items():
        print(f"    {verdict_type}: {count}")
    if result.errors:
        print(f"    [!] {len(result.errors)} findings failed triage — see 'errors' in output")

    return 0


if __name__ == "__main__":
    sys.exit(main())