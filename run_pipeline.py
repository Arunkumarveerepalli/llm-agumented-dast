"""
Full pipeline orchestrator — runs every module in the correct order with
one command, instead of running each module's CLI by hand.

Lives at the project root (same level as recon/, scanning/, llm_triage/,
evaluation/). Each step is invoked as its own subprocess with the working
directory set to that module's folder — this exactly mirrors the manual
commands already validated throughout development, so nothing about how
each module resolves its own relative paths (recon_output.json,
scan_output.json, etc.) changes.

Usage:
    python run_pipeline.py --target dvwa --base-url http://localhost \
        --login-url http://localhost/login.php --model llama3.1:8b --verbose

    # Also generate the naive-baseline comparison data for RQ3:
    python run_pipeline.py --target dvwa --base-url http://localhost \
        --login-url http://localhost/login.php --model llama3.1:8b \
        --with-naive-baseline --verbose

    # Skip recon if recon_output.json is already fresh (saves a crawl):
    python run_pipeline.py --target dvwa --base-url http://localhost \
        --login-url http://localhost/login.php --skip-recon --verbose
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the full recon -> scan -> triage -> eval pipeline in one command.")
    parser.add_argument("--target", required=True, help="Target profile name, e.g. 'dvwa'")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--login-url", required=True)
    parser.add_argument("--model", default="llama3.1:8b", help="Ollama model name for triage")
    parser.add_argument("--security-level", default="low")
    parser.add_argument("--with-naive-baseline", action="store_true",
                         help="Also run a --naive-baseline scan + triage pass, for the RQ3 comparison in evaluation")
    parser.add_argument("--skip-recon", action="store_true", help="Skip recon and reuse the existing recon_output.json")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def run_step(description: str, cmd: list[str], cwd: Path) -> None:
    """Runs one pipeline step as a subprocess, streaming output live. Aborts the whole pipeline with a clear message if the step fails — never continues on bad data."""
    print()
    print(f"{'=' * 70}")
    print(f"  {description}")
    print(f"{'=' * 70}")
    print(f"  cwd: {cwd}")
    print(f"  cmd: {' '.join(cmd)}")
    print()

    result = subprocess.run(cmd, cwd=cwd)  # not capturing output — streams live to the terminal, same as running it by hand

    if result.returncode != 0:
        print()
        print(f"[!!!] PIPELINE STOPPED — step failed: {description}")
        print(f"[!!!] Exit code {result.returncode}. Check the output above for the actual error.")
        print(f"[!!!] Common causes at this stage: DVWA not running (docker ps), login failure, or Ollama not running.")
        sys.exit(1)


def main() -> int:
    args = parse_args()
    py = sys.executable  # use the current venv's Python, not whatever 'python' resolves to on PATH
    verbose_flag = ["--verbose"] if args.verbose else []

    recon_dir = PROJECT_ROOT / "recon"
    scanning_dir = PROJECT_ROOT / "scanning"
    triage_dir = PROJECT_ROOT / "llm_triage"
    eval_dir = PROJECT_ROOT / "evaluation"

    if not args.skip_recon:
        run_step(
            "STEP 1/5 — Recon",
            [py, "run_recon.py", "--target", args.target, "--base-url", args.base_url,
             "--login-url", args.login_url, "--security-level", args.security_level,
             "--output", "recon_output.json"] + verbose_flag,
            cwd=recon_dir,
        )
    else:
        print("\n[*] Skipping recon (--skip-recon) — reusing existing recon/recon_output.json")

    run_step(
        "STEP 2/5 — Scanning (hardened)",
        [py, "run_scan.py", "--target", args.target, "--base-url", args.base_url,
         "--login-url", args.login_url, "--recon-input", "../recon/recon_output.json",
         "--output", "scan_output.json"] + verbose_flag,
        cwd=scanning_dir,
    )

    if args.with_naive_baseline:
        run_step(
            "STEP 2b/5 — Scanning (naive baseline, for RQ3)",
            [py, "run_scan.py", "--target", args.target, "--base-url", args.base_url,
             "--login-url", args.login_url, "--recon-input", "../recon/recon_output.json",
             "--output", "scan_output_raw.json", "--naive-baseline"] + verbose_flag,
            cwd=scanning_dir,
        )

    run_step(
        "STEP 3/5 — LLM Triage (hardened)",
        [py, "run_triage.py", "--scan-input", "../scanning/scan_output.json",
         "--model", args.model, "--output", "triage_output.json"] + verbose_flag,
        cwd=triage_dir,
    )

    if args.with_naive_baseline:
        run_step(
            "STEP 3b/5 — LLM Triage (naive baseline, for RQ3)",
            [py, "run_triage.py", "--scan-input", "../scanning/scan_output_raw.json",
             "--model", args.model, "--output", "triage_output_raw.json"] + verbose_flag,
            cwd=triage_dir,
        )

    eval_cmd = [py, "run_eval.py", "--triage-input", "../llm_triage/triage_output.json",
                "--scan-input", "../scanning/scan_output.json", "--output", "eval_output.json"] + verbose_flag
    if args.with_naive_baseline:
        eval_cmd += ["--naive-triage-input", "../llm_triage/triage_output_raw.json"]

    run_step("STEP 4/5 — Evaluation", eval_cmd, cwd=eval_dir)

    print()
    print("=" * 70)
    print("  PIPELINE COMPLETE")
    print("=" * 70)
    print(f"  recon/recon_output.json")
    print(f"  scanning/scan_output.json" + ("  +  scanning/scan_output_raw.json" if args.with_naive_baseline else ""))
    print(f"  llm_triage/triage_output.json" + ("  +  llm_triage/triage_output_raw.json" if args.with_naive_baseline else ""))
    print(f"  evaluation/eval_output.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())