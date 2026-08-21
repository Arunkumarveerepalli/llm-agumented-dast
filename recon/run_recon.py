"""
Recon module entry point.

Usage:
    python run_recon.py --target dvwa \
        --base-url http://localhost/dvwa \
        --login-url http://localhost/dvwa/login.php \
        --username admin --password password \
        --security-level low \
        --max-depth 5 --max-pages 200 \
        --output recon_output.json
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from dotenv import load_dotenv

from session import TargetProfile, bootstrap_session
from crawler import Crawler


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Recon module — maps a target's attack surface.")
    parser.add_argument("--target", required=True, help="Target profile name, e.g. 'dvwa'")
    parser.add_argument("--base-url", required=True, help="Base URL of the application, e.g. http://localhost/dvwa")
    parser.add_argument("--login-url", required=True, help="Login page URL")
    # Credentials are intentionally NOT CLI args: passing them on the command
    # line puts them in shell history and in `ps aux` output for any user on
    # the machine. They're loaded from environment variables / .env instead.
    parser.add_argument("--security-level", default="low", help="DVWA security level (low/medium/high)")
    parser.add_argument("--max-depth", type=int, default=5)
    parser.add_argument("--max-pages", type=int, default=200)
    parser.add_argument("--output", default="recon_output.json")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def load_credentials() -> tuple[str, str]:
    """Load target credentials from environment (.env in dev, real env vars in CI/prod)."""
    load_dotenv()  # no-op if no .env file present — fine for CI where env is set directly
    username = os.environ.get("TARGET_USERNAME")
    password = os.environ.get("TARGET_PASSWORD")
    if not username or not password:
        print(
            "[!] TARGET_USERNAME / TARGET_PASSWORD not set. "
            "Copy .env.example to .env and fill in credentials, "
            "or export them as environment variables.",
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

    print(f"[*] Crawling from {args.base_url} (max depth={args.max_depth}, max pages={args.max_pages})...")
    crawler = Crawler(
        session=session,
        seed_url=args.base_url,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
    )
    result = crawler.run()

    result.save(args.output)
    print(f"[+] Recon complete: {len(result.endpoints)} endpoints written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())