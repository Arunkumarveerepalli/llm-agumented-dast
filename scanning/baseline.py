"""
Baseline capture.

Before mutating any parameter, fetch the endpoint's normal (unmutated)
response once. Detection compares mutated responses against this baseline
rather than absolute heuristics alone — this cuts down false positives
from pages that always contain certain words (e.g. a page that always
says "error" in its footer).
"""

from __future__ import annotations

import time
import requests


def capture_baseline(
    session: requests.Session, url: str, method: str, form_data: dict | None = None
) -> tuple[str, int, int]:
    """
    Returns (response_text, response_length, response_time_ms) for the
    endpoint's normal, unmutated request. Respects the endpoint's actual
    method: GET params go in the query string, POST data in the body —
    sending GET-only defaults as a POST body would silently test nothing.
    """
    start = time.monotonic()
    if method.upper() == "POST":
        resp = session.post(url, data=form_data or {}, timeout=10)
    else:
        resp = session.get(url, params=form_data or {}, timeout=10)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    return resp.text, len(resp.text), elapsed_ms