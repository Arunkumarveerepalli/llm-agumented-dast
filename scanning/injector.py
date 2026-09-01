"""
Injector — the core orchestrator.

NEW: excludes login/authentication endpoints from testing entirely (see
is_auth_endpoint). Real-world testing showed the scanner treating
login.php as a fuzzable target — sending SQLi/XSS/cmdi/path-traversal
payloads into its username/password fields, since recon captures it as
any other form — coincided with the login step failing consistently for
the REST of the pipeline afterward, immediately following the scan that
hammered it. Whether or not that's the full explanation, fuzzing the
endpoint the whole pipeline depends on for authentication is not a
meaningful vulnerability test anyway (you already know its credentials),
so excluding it is correct regardless.
"""

from __future__ import annotations

import time
import logging

import requests
from bs4 import BeautifulSoup

from models import Finding, VulnClass, ScanResult
from payloads import PAYLOADS, BOOLEAN_SQLI_INDICATORS, TIMING_BASED_PAYLOADS
from baseline import capture_baseline
from detector import detect_sqli, detect_xss, detect_cmdi, detect_path_traversal, detect_boolean_sqli_pair, detect_boolean_sqli_naive

logger = logging.getLogger(__name__)

ALL_CLASSES: list[VulnClass] = list(VulnClass)
SNIPPET_WINDOW = 200
MAX_RETRIES = 2
RETRY_DELAY_SECONDS = 3

# Path fragments identifying an endpoint as authentication infrastructure,
# not a fair fuzzing target. Extend this list if other targets (e.g.
# Juice Shop) use different login paths.
AUTH_ENDPOINT_MARKERS = ["login.php", "logout.php"]


def is_auth_endpoint(url: str) -> bool:
    url_lower = url.lower()
    return any(marker in url_lower for marker in AUTH_ENDPOINT_MARKERS)


def refresh_csrf_token(session: requests.Session, page_url: str, field_name: str) -> str:
    resp = session.get(page_url, timeout=10)
    soup = BeautifulSoup(resp.text, "html.parser")
    token_input = soup.find("input", {"name": field_name})
    return token_input.get("value", "") if token_input else ""


def extract_relevant_snippet(response_text: str, payload: str) -> str:
    from payloads import SQL_ERROR_STRINGS, CMDI_MARKERS, PATH_TRAVERSAL_MARKERS
    search_terms = [payload] + SQL_ERROR_STRINGS + CMDI_MARKERS + PATH_TRAVERSAL_MARKERS
    lower_text = response_text.lower()

    for term in search_terms:
        if not term:
            continue
        idx = lower_text.find(term.lower())
        if idx != -1:
            start = max(0, idx - SNIPPET_WINDOW)
            end = min(len(response_text), idx + len(term) + SNIPPET_WINDOW)
            prefix = "..." if start > 0 else ""
            suffix = "..." if end < len(response_text) else ""
            return f"{prefix}{response_text[start:end]}{suffix}"

    return response_text[:300]


def run_detector(vuln_class: VulnClass, payload: str, response_text: str, baseline_text: str, response_time_ms: int, naive_mode: bool = False):
    if vuln_class == VulnClass.SQLI:
        if naive_mode and payload in BOOLEAN_SQLI_INDICATORS:
            return detect_boolean_sqli_naive(payload, response_text, baseline_text)
        return detect_sqli(payload, response_text, response_time_ms, baseline_text)
    if vuln_class == VulnClass.XSS:
        return detect_xss(payload, response_text)
    if vuln_class == VulnClass.CMDI:
        return detect_cmdi(response_text, baseline_text)
    if vuln_class == VulnClass.PATH_TRAVERSAL:
        return detect_path_traversal(response_text, baseline_text)
    raise ValueError(f"No detector wired up for {vuln_class}")


def record_if_detected(result: ScanResult, detected, confidence, evidence, endpoint, param, vuln_class, payload, response_text, elapsed_ms, baseline_len):
    result.total_tests_run += 1
    if not detected:
        return
    result.add(Finding(
        id=result._next_id(), endpoint=endpoint, param=param, vuln_class=vuln_class,
        confidence=confidence, payload=payload, evidence=evidence,
        response_snippet=extract_relevant_snippet(response_text, payload),
        response_time_ms=elapsed_ms, baseline_length=baseline_len, response_length=len(response_text),
    ))


def test_boolean_sqli_for_param(send_fn, param_name: str, baseline_text: str, baseline_len: int, result: ScanResult, url: str) -> None:
    payloads = sorted(BOOLEAN_SQLI_INDICATORS)
    or_payload, and_payload = payloads[0], payloads[1]
    or_text, or_ms = send_fn(or_payload)
    and_text, and_ms = send_fn(and_payload)
    or_detected, and_detected, confidence, evidence = detect_boolean_sqli_pair(or_text, and_text, baseline_text, or_payload, and_payload)
    record_if_detected(result, or_detected, confidence, evidence, url, param_name, VulnClass.SQLI, or_payload, or_text, or_ms, baseline_len)
    record_if_detected(result, and_detected, confidence, evidence, url, param_name, VulnClass.SQLI, and_payload, and_text, and_ms, baseline_len)


def test_query_param_endpoint(session: requests.Session, endpoint: dict, result: ScanResult, naive_mode: bool = False) -> None:
    url = endpoint["url"]
    params = endpoint["params"]
    classes = ALL_CLASSES
    baseline_text, baseline_len, _ = capture_baseline(session, url, "GET")

    for param in params:
        param_name = param["name"]
        for vuln_class in classes:
            for payload in PAYLOADS[vuln_class]:
                if payload in BOOLEAN_SQLI_INDICATORS and not naive_mode:
                    continue
                mutated_params = {p["name"]: p.get("default_value", "") for p in params}
                mutated_params[param_name] = payload
                start = time.monotonic()
                request_timeout = 20 if payload in TIMING_BASED_PAYLOADS else 10
                resp = session.get(url.split("?")[0], params=mutated_params, timeout=request_timeout)
                elapsed_ms = int((time.monotonic() - start) * 1000)
                detected, confidence, evidence = run_detector(vuln_class, payload, resp.text, baseline_text, elapsed_ms, naive_mode)
                record_if_detected(result, detected, confidence, evidence, url, param_name, vuln_class, payload, resp.text, elapsed_ms, baseline_len)

        if naive_mode:
            continue

        def send_fn(payload: str, _params=params, _param_name=param_name):
            mutated = {p["name"]: p.get("default_value", "") for p in _params}
            mutated[_param_name] = payload
            start = time.monotonic()
            resp = session.get(url.split("?")[0], params=mutated, timeout=10)
            return resp.text, int((time.monotonic() - start) * 1000)

        test_boolean_sqli_for_param(send_fn, param_name, baseline_text, baseline_len, result, url)


def test_form_endpoint(session: requests.Session, endpoint: dict, result: ScanResult, naive_mode: bool = False) -> None:
    url = endpoint["url"]
    form = endpoint["form"]
    method = endpoint["method"]
    classes = ALL_CLASSES

    baseline_data = {p["name"]: p.get("default_value", "") for p in endpoint["params"]}
    baseline_data.update(form.get("submit_fields", {}))
    baseline_text, baseline_len, _ = capture_baseline(session, url, method, baseline_data)

    for param in endpoint["params"]:
        param_name = param["name"]
        if param_name == form.get("csrf_field_name"):
            continue

        for vuln_class in classes:
            for payload in PAYLOADS[vuln_class]:
                if payload in BOOLEAN_SQLI_INDICATORS and not naive_mode:
                    continue
                mutated_data = {p["name"]: p.get("default_value", "") for p in endpoint["params"]}
                mutated_data.update(form.get("submit_fields", {}))
                mutated_data[param_name] = payload
                if form.get("has_csrf_token") and form.get("csrf_field_name"):
                    fresh_token = refresh_csrf_token(session, url, form["csrf_field_name"])
                    mutated_data[form["csrf_field_name"]] = fresh_token
                start = time.monotonic()
                request_timeout = 20 if payload in TIMING_BASED_PAYLOADS else 10
                if method.upper() == "GET":
                    resp = session.get(url, params=mutated_data, timeout=request_timeout)
                else:
                    resp = session.post(url, data=mutated_data, timeout=request_timeout)
                elapsed_ms = int((time.monotonic() - start) * 1000)
                detected, confidence, evidence = run_detector(vuln_class, payload, resp.text, baseline_text, elapsed_ms, naive_mode)
                record_if_detected(result, detected, confidence, evidence, url, param_name, vuln_class, payload, resp.text, elapsed_ms, baseline_len)

        if naive_mode:
            continue

        def send_fn(payload: str, _endpoint=endpoint, _form=form, _param_name=param_name):
            mutated = {p["name"]: p.get("default_value", "") for p in _endpoint["params"]}
            mutated.update(_form.get("submit_fields", {}))
            mutated[_param_name] = payload
            if _form.get("has_csrf_token") and _form.get("csrf_field_name"):
                mutated[_form["csrf_field_name"]] = refresh_csrf_token(session, url, _form["csrf_field_name"])
            start = time.monotonic()
            if method.upper() == "GET":
                resp = session.get(url, params=mutated, timeout=10)
            else:
                resp = session.post(url, data=mutated, timeout=10)
            return resp.text, int((time.monotonic() - start) * 1000)

        test_boolean_sqli_for_param(send_fn, param_name, baseline_text, baseline_len, result, url)


def run_scan(session: requests.Session, recon_data: dict, target_name: str = "dvwa", naive_mode: bool = False) -> ScanResult:
    result = ScanResult(target=recon_data["target"])
    logger.info("Starting scan against target profile '%s'%s", target_name, " (NAIVE mode)" if naive_mode else "")

    skipped_auth_endpoints = 0

    for endpoint in recon_data["endpoints"]:
        url = endpoint["url"]

        if is_auth_endpoint(url):
            logger.info("Skipping authentication endpoint (not a fair fuzzing target): %s", url)
            skipped_auth_endpoints += 1
            continue

        logger.info("Scanning endpoint: %s", url)

        last_exc = None
        for attempt in range(1, MAX_RETRIES + 2):
            findings_snapshot = len(result.findings)
            tests_snapshot = result.total_tests_run
            try:
                if endpoint.get("form"):
                    test_form_endpoint(session, endpoint, result, naive_mode)
                else:
                    test_query_param_endpoint(session, endpoint, result, naive_mode)
                last_exc = None
                break
            except requests.RequestException as exc:
                last_exc = exc
                del result.findings[findings_snapshot:]
                result.total_tests_run = tests_snapshot
                if attempt <= MAX_RETRIES:
                    logger.warning("Attempt %d/%d failed for %s: %s — retrying in %ds", attempt, MAX_RETRIES + 1, url, exc, RETRY_DELAY_SECONDS)
                    time.sleep(RETRY_DELAY_SECONDS)
                else:
                    logger.warning("Final attempt failed for %s: %s — giving up", url, exc)

        if last_exc is not None:
            result.add_error(url, str(last_exc))

    if skipped_auth_endpoints:
        logger.info("Skipped %d authentication endpoint(s) — not tested as vulnerability targets", skipped_auth_endpoints)

    logger.info("Scan complete: %d test cases run, %d findings", result.total_tests_run, len(result.findings))
    return result