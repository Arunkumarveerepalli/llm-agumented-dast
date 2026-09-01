from __future__ import annotations

import time
import requests


def capture_baseline(
    session: requests.Session, url: str, method: str, form_data: dict | None = None
) -> tuple[str, int, int]:
    start = time.monotonic()
    if method.upper() == "POST":
        resp = session.post(url, data=form_data or {}, timeout=10)
    else:
        resp = session.get(url, params=form_data or {}, timeout=10)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    return resp.text, len(resp.text), elapsed_ms