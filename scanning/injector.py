"""
Injector — the core orchestrator.

For each endpoint from recon_output.json:
  1. Infer which vuln classes are worth testing (path_inference)
  2. Capture a baseline (unmutated) response
  3. For each param, for each relevant payload:
       - if the endpoint is a form with a CSRF token, re-fetch a FRESH
         token immediately before submitting (DVWA tokens can be
         short-lived/single-use — reusing recon's snapshot silently
         breaks POST-based tests)
       - mutate exactly one param, leave the rest at default values
       - send the request, run the matching detector, record a Finding
"""

from __future__ import annotations

import time
import logging

import requests
from bs4 import BeautifulSoup

from models import Finding, VulnClass, ScanResult
from payloads import PAYLOADS
from baseline import capture_baseline
from detector import detect_sqli, detect_xss, detect_cmdi, detect_path_traversal

logger = logging.getLogger(__name__)

# All four vuln classes are tested against every endpoint/param, regardless
# of target. Slower than path-based inference, but portable: this is what
# lets the tool point at any server-rendered web app, not just DVWA's known
# URL layout. See dissertation Limitations for the trade-off this replaces.
ALL_CLASSES: list[VulnClass] = list(VulnClass)


def refresh_csrf_token(session: requests.Session, page_url: str, field_name: str) -> str:
    """Re-fetches the page and pulls a fresh CSRF token value right before submission."""
    resp = session.get(page_url, timeout=10)
    soup = BeautifulSoup(resp.text, "html.parser")
    token_input = soup.find("input", {"name": field_name})
    return token_input.get("value", "") if token_input else ""


def run_detector(vuln_class: VulnClass, payload: str, response_text: str, baseline_text: str, response_time_ms: int) -> tuple[bool, str]:
    if vuln_class == VulnClass.SQLI:
        return detect_sqli(payload, response_text, response_time_ms)
    if vuln_class == VulnClass.XSS:
        return detect_xss(payload, response_text)
    if vuln_class == VulnClass.CMDI:
        return detect_cmdi(response_text, baseline_text)
    if vuln_class == VulnClass.PATH_TRAVERSAL:
        return detect_path_traversal(response_text, baseline_text)
    raise ValueError(f"No detector wired up for {vuln_class}")


def test_query_param_endpoint(
    session: requests.Session, endpoint: dict, result: ScanResult
) -> None:
    url = endpoint["url"]
    params = endpoint["params"]
    classes = ALL_CLASSES

    baseline_text, baseline_len, _ = capture_baseline(session, url, "GET")

    for param in params:
        param_name = param["name"]
        for vuln_class in classes:
            for payload in PAYLOADS[vuln_class]:
                # Rebuild query params with this one param mutated, others at default
                mutated_params = {p["name"]: p.get("default_value", "") for p in params}
                mutated_params[param_name] = payload

                start = time.monotonic()
                resp = session.get(url.split("?")[0], params=mutated_params, timeout=10)
                elapsed_ms = int((time.monotonic() - start) * 1000)

                detected, evidence = run_detector(vuln_class, payload, resp.text, baseline_text, elapsed_ms)

                result.add(Finding(
                    endpoint=url,
                    param=param_name,
                    vuln_class=vuln_class,
                    payload=payload,
                    detected=detected,
                    evidence=evidence,
                    response_snippet=resp.text[:300],
                    response_time_ms=elapsed_ms,
                    baseline_length=baseline_len,
                    response_length=len(resp.text),
                ))


def test_form_endpoint(
    session: requests.Session, endpoint: dict, result: ScanResult
) -> None:
    url = endpoint["url"]
    form = endpoint["form"]
    method = endpoint["method"]
    classes = ALL_CLASSES

    baseline_data = {p["name"]: p.get("default_value", "") for p in endpoint["params"]}
    baseline_text, baseline_len, _ = capture_baseline(session, url, method, baseline_data)

    for param in endpoint["params"]:
        param_name = param["name"]
        if param_name == form.get("csrf_field_name"):
            continue  # never inject payloads into the CSRF token field itself

        for vuln_class in classes:
            for payload in PAYLOADS[vuln_class]:
                mutated_data = {p["name"]: p.get("default_value", "") for p in endpoint["params"]}
                mutated_data[param_name] = payload

                # Refresh CSRF token immediately before submission if this form uses one
                if form.get("has_csrf_token") and form.get("csrf_field_name"):
                    fresh_token = refresh_csrf_token(session, url, form["csrf_field_name"])
                    mutated_data[form["csrf_field_name"]] = fresh_token

                start = time.monotonic()
                resp = session.post(url, data=mutated_data, timeout=10)
                elapsed_ms = int((time.monotonic() - start) * 1000)

                detected, evidence = run_detector(vuln_class, payload, resp.text, baseline_text, elapsed_ms)

                result.add(Finding(
                    endpoint=url,
                    param=param_name,
                    vuln_class=vuln_class,
                    payload=payload,
                    detected=detected,
                    evidence=evidence,
                    response_snippet=resp.text[:300],
                    response_time_ms=elapsed_ms,
                    baseline_length=baseline_len,
                    response_length=len(resp.text),
                ))


def run_scan(session: requests.Session, recon_data: dict, target_name: str = "dvwa") -> ScanResult:
    result = ScanResult(target=recon_data["target"])
    logger.info("Starting scan against target profile '%s' (all vuln classes on every endpoint)", target_name)

    for endpoint in recon_data["endpoints"]:
        logger.info("Scanning endpoint: %s", endpoint["url"])
        try:
            if endpoint.get("form"):
                test_form_endpoint(session, endpoint, result)
            else:
                test_query_param_endpoint(session, endpoint, result)
        except requests.RequestException as exc:
            logger.warning("Failed to test %s: %s", endpoint["url"], exc)
            continue

    logger.info("Scan complete: %d findings", len(result.findings))
    return result
