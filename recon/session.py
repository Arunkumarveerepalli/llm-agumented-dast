"""
Session bootstrap.

Root cause finally confirmed via Apache access logs: DVWA's login POST
returned 302 (success) on every single attempt from python-requests --
100% success at the server. The failures were a bug in OUR OWN
success-detection logic: it checked where the request ended up AFTER
requests automatically followed the redirect, not what DVWA's login
response itself said. If the auto-followed GET to index.php raced ahead
of the session write finishing, it could bounce back to login.php,
making a genuinely successful login look like a failure.

Fix: disable automatic redirect-following on the login POST and check
the POST's own status code directly (301/302/303 = DVWA accepted the
login). Session.post() still stores any Set-Cookie headers from that
response into the session before we even decide whether to follow the
redirect, so the session is already authenticated the moment we see a
302 -- no need to chase the redirect at all to get a working session for
the crawler/scanner to use afterward.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import requests
from bs4 import BeautifulSoup


@dataclass
class TargetProfile:
    name: str
    base_url: str
    login_url: str
    username: str
    password: str
    extra: dict = field(default_factory=dict)


def bootstrap_dvwa_session(profile: TargetProfile) -> requests.Session:
    session = requests.Session()

    login_page = session.get(profile.login_url, timeout=15)
    soup = BeautifulSoup(login_page.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    if token_input is None:
        raise RuntimeError(
            f"Could not find CSRF token on login page {profile.login_url}. "
            "Is DVWA running and reachable at this URL?"
        )
    csrf_token = token_input.get("value", "")

    login_payload = {
        "username": profile.username,
        "password": profile.password,
        "Login": "Login",
        "user_token": csrf_token,
    }

    # allow_redirects=False is the actual fix: judge DVWA's login response
    # on its own terms, not on wherever automatic redirect-following ends
    # up landing.
    resp = session.post(profile.login_url, data=login_payload, timeout=15, allow_redirects=False)

    if resp.status_code in (301, 302, 303):
        # Success -- DVWA told us to redirect (almost always to index.php).
        # The session object already has whatever cookies this response
        # set. We don't need to actually follow the redirect for the
        # session to be usable by the crawler/scanner afterward.
        pass
    elif resp.status_code == 200 and "login failed" in resp.text.lower():
        raise RuntimeError(
            f"DVWA login failed -- credentials rejected. "
            f"HTTP {resp.status_code}, response text: "
            f"{BeautifulSoup(resp.text, 'html.parser').get_text(separator=' ', strip=True)[:300]!r}"
        )
    else:
        raise RuntimeError(
            f"DVWA login gave an unexpected response -- HTTP {resp.status_code}, "
            f"body starts with: {resp.text[:200]!r}"
        )

    security_level = profile.extra.get("security_level", "low")
    security_url = f"{profile.base_url.rstrip('/')}/security.php"
    sec_page = session.get(security_url, timeout=15)
    sec_soup = BeautifulSoup(sec_page.text, "html.parser")
    sec_token_input = sec_soup.find("input", {"name": "user_token"})
    sec_token = sec_token_input.get("value", "") if sec_token_input else ""

    session.post(
        security_url,
        data={"security": security_level, "seclev_submit": "Submit", "user_token": sec_token},
        timeout=15,
    )

    return session


def bootstrap_session(profile: TargetProfile) -> requests.Session:
    if profile.name.lower() == "dvwa":
        return bootstrap_dvwa_session(profile)
    raise NotImplementedError(f"No session bootstrap implemented for target '{profile.name}' yet.")