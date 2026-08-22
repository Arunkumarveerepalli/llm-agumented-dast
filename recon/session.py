"""
Session bootstrap.

Recon needs an authenticated requests.Session before crawling can start.
DVWA requires: (1) log in with credentials + CSRF token, (2) set the
security level cookie. This module keeps that logic behind a small
TargetProfile abstraction so Juice Shop (or another target) can be added
later without touching the crawler.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import requests
from bs4 import BeautifulSoup


@dataclass
class TargetProfile:
    name: str
    base_url: str                      # e.g. "http://localhost/dvwa"
    login_url: str                     # e.g. "http://localhost/dvwa/login.php"
    username: str
    password: str
    extra: dict = field(default_factory=dict)  # target-specific knobs (e.g. security level)


def bootstrap_dvwa_session(profile: TargetProfile) -> requests.Session:
    """
    Logs into DVWA and sets the security level cookie.
    Returns an authenticated requests.Session ready for the crawler.
    """
    session = requests.Session()

    # Step 1: GET the login page to grab the CSRF token DVWA embeds in the form
    login_page = session.get(profile.login_url, timeout=10)
    soup = BeautifulSoup(login_page.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    if token_input is None:
        raise RuntimeError(
            f"Could not find CSRF token on login page {profile.login_url}. "
            "Is DVWA running and reachable at this URL?"
        )
    csrf_token = token_input.get("value", "")

    # Step 2: POST credentials + token
    login_payload = {
        "username": profile.username,
        "password": profile.password,
        "Login": "Login",
        "user_token": csrf_token,
    }
    resp = session.post(profile.login_url, data=login_payload, timeout=10)

    if "login.php" in resp.url.lower() or "login failed" in resp.text.lower():
        raise RuntimeError(
            "DVWA login failed — check credentials in TargetProfile. "
            "(Detected: still on login.php after POST, or a 'login failed' message in the response.)"
        )

    # Step 3: set security level (low/medium/high), stored in profile.extra
    security_level = profile.extra.get("security_level", "low")
    security_url = f"{profile.base_url.rstrip('/')}/security.php"
    sec_page = session.get(security_url, timeout=10)
    sec_soup = BeautifulSoup(sec_page.text, "html.parser")
    sec_token_input = sec_soup.find("input", {"name": "user_token"})
    sec_token = sec_token_input.get("value", "") if sec_token_input else ""

    session.post(
        security_url,
        data={
            "security": security_level,
            "seclev_submit": "Submit",
            "user_token": sec_token,
        },
        timeout=10,
    )

    return session


def bootstrap_session(profile: TargetProfile) -> requests.Session:
    """
    Dispatches to the right bootstrap routine based on profile.name.
    Add new branches here (e.g. "juice_shop") without touching callers.
    """
    if profile.name.lower() == "dvwa":
        return bootstrap_dvwa_session(profile)

    raise NotImplementedError(
        f"No session bootstrap implemented for target '{profile.name}' yet."
    )