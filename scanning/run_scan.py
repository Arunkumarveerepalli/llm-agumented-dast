"""
Scanning module entry point.

Usage:
    python run_scan.py --target dvwa \
        --base-url http://localhost \
        --login-url http://localhost/login.php \
        --recon-input ../recon/recon_output.json \
        --output scan_output.json --verbose

Reuses the exact same session bootstrap and credential-loading pattern
as recon/run_recon.py — same TargetProfile, same .env, same reasoning
for why credentials never touch the CLI.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

# Reuse recon's session bootstrap without polluting sys.path — recon/ and
# scanning/ each have their own models.py with different contents, and a
# blanket sys.path.insert would let recon's models.py shadow scanning's,
# which is exactly what happened during testing. Loading session.py by
# exact file path avoids the collision entirely.
import importlib.util

_RECON_SESSION_PATH = os.path.join(os.path.dirname(__file__), "..", "recon", "session.py")
_spec = importlib.util.spec_from_file_location("recon_session", _RECON_SESSION_PATH)
_recon_session = importlib.util.module_from_spec(_spec)
sys.modules["recon_session"] = _recon_session  # required so dataclass/etc. can resolve this module
_spec.loader.exec_module(_recon_session)
TargetProfile = _recon_session.TargetProfile
bootstrap_session = _recon_session.bootstrap_session

from dotenv import load_dotenv

from injector import run_scan


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scanning module — injects payloads based on recon output.")
    parser.add_argument("--target", required=True, help="Target profile name, e.g. 'dvwa'")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--login-url", required=True)
    parser.add_argument("--security-level", default="low")
    parser.add_argument("--recon-input", required=True, help="Path to recon_output.json")
    parser.add_argument("--output", default="scan_output.json")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--naive-baseline", action="store_true",
        help="Use a naive (non-differential) boolean-SQLi detector instead of the hardened one. "
             "Generates a deliberately noisier 'raw scanner output' baseline for the RQ3 "
             "false-positive-reduction comparison — not for normal scanning use.",
    )
    return parser.parse_args()


def load_credentials() -> tuple[str, str]:
    load_dotenv()
    username = os.environ.get("TARGET_USERNAME")
    password = os.environ.get("TARGET_PASSWORD")
    if not username or not password:
        print(
            "[!] TARGET_USERNAME / TARGET_PASSWORD not set. "
            "Copy .env.example to .env and fill in credentials.",
            file=sys.stderr,
        )
        sys.exit(1)
    return username, password


def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    username, password = load_credentials()

    profile = TargetProfile(
        name=args.target,
        base_url=args.base_url,
        login_url=args.login_url,
        username=username,
        password=password,
        extra={"security_level": args.security_level},
    )

    print(f"[*] Bootstrapping session for target '{args.target}'...")
    try:
        session = bootstrap_session(profile)
    except (RuntimeError, NotImplementedError) as exc:
        print(f"[!] Session bootstrap failed: {exc}", file=sys.stderr)
        return 1

    print(f"[*] Loading recon data from {args.recon_input}...")
    try:
        with open(args.recon_input, "r", encoding="utf-8") as f:
            recon_data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Recon input file not found: {args.recon_input}", file=sys.stderr)
        return 1

    print(f"[*] Scanning {len(recon_data['endpoints'])} endpoints...")
    result = run_scan(session, recon_data, target_name=args.target, naive_mode=args.naive_baseline)

    result.save(args.output)
    print(f"[+] Scan complete: {result.total_tests_run} test cases run, {len(result.findings)} findings written to {args.output}")

    by_class = {}
    for f in result.findings:
        by_class[f.vuln_class.value] = by_class.get(f.vuln_class.value, 0) + 1
    for cls, count in sorted(by_class.items()):
        print(f"    {cls}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())