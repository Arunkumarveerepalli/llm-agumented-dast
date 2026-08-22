"""
Injector — the core orchestrator.

For each endpoint from recon_output.json:
  1. Capture a baseline (unmutated) response
  2. For each param, for each relevant payload:
       - if the endpoint is a form with a CSRF token, re-fetch a FRESH
         token immediately before submitting (DVWA tokens can be
         short-lived/single-use — reusing recon's snapshot silently
         breaks POST-based tests)
       - always send the form's submit_fields unchanged (many apps only
         run their query/logic if these are present — dropping them
         silently breaks the test rather than erroring)
       - mutate exactly one param, leave the rest at default values
       - send the request, run the matching detector, record a Finding
         ONLY if detected — see models.py for why non-detections aren't
         written to the output
  3. The two boolean-based SQLi payloads (' OR '1'='1 / 1' AND '1'='2)
     are tested together via test_boolean_sqli_for_param, not
     independently — see detector.detect_boolean_sqli_pair for why.

Every test case counts toward result.total_tests_run whether or not it
produced a Finding, so the summary block stays accurate even though only
detections get written out in full.
"""

from __future__ import annotations

import time
import logging

import requests
from bs4 import BeautifulSoup

from models import Finding, VulnClass, ScanResult
from payloads import PAYLOADS, BOOLEAN_SQLI_INDICATORS, TIMING_BASED_PAYLOADS, SQL_ERROR_STRINGS, CMDI_MARKERS, PATH_TRAVERSAL_MARKERS
from baseline import capture_baseline
from detector import detect_sqli, detect_xss, detect_cmdi, detect_path_traversal, detect_boolean_sqli_pair

logger = logging.getLogger(__name__)

SNIPPET_WINDOW = 200  # chars of context on each side of the found evidence

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


def extract_relevant_snippet(response_text: str, payload: str) -> str:
    """
    Returns a window of text centered on wherever the actual evidence
    appears in the response, instead of blindly taking the first N
    characters — which, for real HTML pages, is almost always just
    boilerplate (DOCTYPE, head, title) that never contains the finding
    itself. Every downstream consumer of this snippet (the LLM triage
    layer especially) needs to actually be able to SEE the evidence it's
    being asked to judge.

    Search order: the payload itself (covers XSS reflection, and SQLi/
    cmdi/path-traversal cases where the payload string still appears,
    e.g. in an error message quoting the input) -> known detection
    markers (SQL error strings, command-output markers, file-content
    markers) -> fallback to the first chunk of the response if nothing
    matched (e.g. a pure timing-based SQLi finding, where the response
    body itself carries no direct textual evidence at all).
    """
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

    # Nothing found verbatim (e.g. pure timing-based detection, or a
    # boolean-SQLi finding whose evidence is response SHAPE, not text) —
    # first 300 chars is a reasonable fallback here since there's no
    # better location to center on.
    return response_text[:300]


def run_detector(vuln_class: VulnClass, payload: str, response_text: str, baseline_text: str, response_time_ms: int):
    if vuln_class == VulnClass.SQLI:
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
        id=result._next_id(),
        endpoint=endpoint,
        param=param,
        vuln_class=vuln_class,
        confidence=confidence,
        payload=payload,
        evidence=evidence,
        response_snippet=extract_relevant_snippet(response_text, payload),
        response_time_ms=elapsed_ms,
        baseline_length=baseline_len,
        response_length=len(response_text),
    ))


def test_boolean_sqli_for_param(
    send_fn, param_name: str, baseline_text: str, baseline_len: int, result: ScanResult, url: str
) -> None:
    """
    Shared by both endpoint types: sends the OR-condition and AND-condition
    payloads, judges them together via detect_boolean_sqli_pair (see that
    function for why they can't be judged independently), and records a
    Finding per payload that came back detected.

    send_fn(payload) -> (response_text, elapsed_ms) — supplied by the
    caller so this works for both plain query params and form submissions
    (which need CSRF refresh + submit fields baked in per request).
    """
    payloads = sorted(BOOLEAN_SQLI_INDICATORS)  # deterministic order: OR before AND
    or_payload, and_payload = payloads[0], payloads[1]

    or_text, or_ms = send_fn(or_payload)
    and_text, and_ms = send_fn(and_payload)

    or_detected, and_detected, confidence, evidence = detect_boolean_sqli_pair(
        or_text, and_text, baseline_text, or_payload, and_payload
    )

    record_if_detected(result, or_detected, confidence, evidence, url, param_name, VulnClass.SQLI, or_payload, or_text, or_ms, baseline_len)
    record_if_detected(result, and_detected, confidence, evidence, url, param_name, VulnClass.SQLI, and_payload, and_text, and_ms, baseline_len)


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
                if payload in BOOLEAN_SQLI_INDICATORS:
                    continue  # handled together below, not independently

                mutated_params = {p["name"]: p.get("default_value", "") for p in params}
                mutated_params[param_name] = payload

                start = time.monotonic()
                # SLEEP-based payloads deliberately slow the response by
                # design — give them extra headroom so a legitimate 2s
                # delay under normal load doesn't get mistaken for a
                # hung connection and abort the whole endpoint's tests.
                request_timeout = 20 if payload in TIMING_BASED_PAYLOADS else 10
                resp = session.get(url.split("?")[0], params=mutated_params, timeout=request_timeout)
                elapsed_ms = int((time.monotonic() - start) * 1000)

                detected, confidence, evidence = run_detector(vuln_class, payload, resp.text, baseline_text, elapsed_ms)
                record_if_detected(result, detected, confidence, evidence, url, param_name, vuln_class, payload, resp.text, elapsed_ms, baseline_len)

        def send_fn(payload: str, _params=params, _param_name=param_name):
            mutated = {p["name"]: p.get("default_value", "") for p in _params}
            mutated[_param_name] = payload
            start = time.monotonic()
            resp = session.get(url.split("?")[0], params=mutated, timeout=10)
            return resp.text, int((time.monotonic() - start) * 1000)

        test_boolean_sqli_for_param(send_fn, param_name, baseline_text, baseline_len, result, url)


def test_form_endpoint(
    session: requests.Session, endpoint: dict, result: ScanResult
) -> None:
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
            continue  # never inject payloads into the CSRF token field itself

        for vuln_class in classes:
            for payload in PAYLOADS[vuln_class]:
                if payload in BOOLEAN_SQLI_INDICATORS:
                    continue  # handled together below, not independently

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

                detected, confidence, evidence = run_detector(vuln_class, payload, resp.text, baseline_text, elapsed_ms)
                record_if_detected(result, detected, confidence, evidence, url, param_name, vuln_class, payload, resp.text, elapsed_ms, baseline_len)

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


MAX_RETRIES = 2
RETRY_DELAY_SECONDS = 3


def run_scan(session: requests.Session, recon_data: dict, target_name: str = "dvwa") -> ScanResult:
    result = ScanResult(target=recon_data["target"])
    logger.info("Starting scan against target profile '%s' (all vuln classes on every endpoint)", target_name)

    for endpoint in recon_data["endpoints"]:
        url = endpoint["url"]
        logger.info("Scanning endpoint: %s", url)

        last_exc = None
        for attempt in range(1, MAX_RETRIES + 2):  # initial attempt + MAX_RETRIES retries
            # Snapshot state so a retry can roll back any tests that
            # completed before a mid-loop failure — otherwise a timeout
            # partway through would cause the retry to double-count the
            # payloads that already succeeded.
            findings_snapshot = len(result.findings)
            tests_snapshot = result.total_tests_run

            try:
                if endpoint.get("form"):
                    test_form_endpoint(session, endpoint, result)
                else:
                    test_query_param_endpoint(session, endpoint, result)
                last_exc = None
                break
            except requests.RequestException as exc:
                last_exc = exc
                del result.findings[findings_snapshot:]
                result.total_tests_run = tests_snapshot
                if attempt <= MAX_RETRIES:
                    logger.warning(
                        "Attempt %d/%d failed for %s: %s — retrying in %ds",
                        attempt, MAX_RETRIES + 1, url, exc, RETRY_DELAY_SECONDS,
                    )
                    time.sleep(RETRY_DELAY_SECONDS)
                else:
                    logger.warning("Final attempt failed for %s: %s — giving up", url, exc)

        if last_exc is not None:
            result.add_error(url, str(last_exc))

    logger.info("Scan complete: %d test cases run, %d findings", result.total_tests_run, len(result.findings))
    return result