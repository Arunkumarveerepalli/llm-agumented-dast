"""
Full pipeline orchestrator.

Includes a cooldown pause between steps that each bootstrap their own
DVWA session (recon, scan, scan --naive-baseline) -- real testing showed
login becoming unreliable specifically on the 3rd such bootstrap within
one pipeline run, and giving DVWA a short breather between heavy steps
is a pragmatic mitigation alongside session.py's own increased retry
headroom, regardless of the exact underlying cause.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
STEP_COOLDOWN_SECONDS = 8


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the full recon -> scan -> triage -> eval pipeline in one command.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--login-url", required=True)
    parser.add_argument("--model", default="llama3.1:8b")
    parser.add_argument("--security-level", default="low")
    parser.add_argument("--with-naive-baseline", action="store_true")
    parser.add_argument("--skip-recon", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def run_step(description: str, cmd: list[str], cwd: Path) -> None:
    print()
    print(f"{'=' * 70}")
    print(f"  {description}")
    print(f"{'=' * 70}")
    print(f"  cwd: {cwd}")
    print(f"  cmd: {' '.join(cmd)}")
    print()

    result = subprocess.run(cmd, cwd=cwd)

    if result.returncode != 0:
        print()
        print(f"[!!!] PIPELINE STOPPED -- step failed: {description}")
        print(f"[!!!] Exit code {result.returncode}. Check the output above for the actual error.")
        print(f"[!!!] Common causes at this stage: DVWA not running (docker ps), login failure, or Ollama not running.")
        sys.exit(1)


def cooldown(reason: str) -> None:
    print(f"\n[*] Cooling down {STEP_COOLDOWN_SECONDS}s before next step ({reason}) -- lets DVWA settle between heavy operations...")
    time.sleep(STEP_COOLDOWN_SECONDS)


def main() -> int:
    args = parse_args()
    py = sys.executable
    verbose_flag = ["--verbose"] if args.verbose else []

    recon_dir = PROJECT_ROOT / "recon"
    scanning_dir = PROJECT_ROOT / "scanning"
    triage_dir = PROJECT_ROOT / "llm_triage"
    eval_dir = PROJECT_ROOT / "evaluation"

    if not args.skip_recon:
        run_step(
            "STEP 1/5 -- Recon",
            [py, "run_recon.py", "--target", args.target, "--base-url", args.base_url,
             "--login-url", args.login_url, "--security-level", args.security_level,
             "--output", "recon_output.json"] + verbose_flag,
            cwd=recon_dir,
        )
        cooldown("next step also logs into DVWA")
    else:
        print("\n[*] Skipping recon (--skip-recon) -- reusing existing recon/recon_output.json")

    run_step(
        "STEP 2/5 -- Scanning (hardened)",
        [py, "run_scan.py", "--target", args.target, "--base-url", args.base_url,
         "--login-url", args.login_url, "--recon-input", "../recon/recon_output.json",
         "--output", "scan_output.json"] + verbose_flag,
        cwd=scanning_dir,
    )

    if args.with_naive_baseline:
        cooldown("next step also logs into DVWA")
        run_step(
            "STEP 2b/5 -- Scanning (naive baseline, for RQ3)",
            [py, "run_scan.py", "--target", args.target, "--base-url", args.base_url,
             "--login-url", args.login_url, "--recon-input", "../recon/recon_output.json",
             "--output", "scan_output_raw.json", "--naive-baseline"] + verbose_flag,
            cwd=scanning_dir,
        )

    run_step(
        "STEP 3/5 -- LLM Triage (hardened)",
        [py, "run_triage.py", "--scan-input", "../scanning/scan_output.json",
         "--model", args.model, "--output", "triage_output.json"] + verbose_flag,
        cwd=triage_dir,
    )

    if args.with_naive_baseline:
        run_step(
            "STEP 3b/5 -- LLM Triage (naive baseline, for RQ3)",
            [py, "run_triage.py", "--scan-input", "../scanning/scan_output_raw.json",
             "--model", args.model, "--output", "triage_output_raw.json"] + verbose_flag,
            cwd=triage_dir,
        )

    eval_cmd = [py, "run_eval.py", "--triage-input", "../llm_triage/triage_output.json",
                "--scan-input", "../scanning/scan_output.json", "--output", "eval_output.json"] + verbose_flag
    if args.with_naive_baseline:
        eval_cmd += ["--naive-triage-input", "../llm_triage/triage_output_raw.json"]

    run_step("STEP 4/5 -- Evaluation", eval_cmd, cwd=eval_dir)

    print()
    print("=" * 70)
    print("  PIPELINE COMPLETE")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
    