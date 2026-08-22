"""
Signature-based detection, one function per vuln class.

Each detector returns (detected: bool, evidence: str). This is the
"first pass" — deliberately simple pattern matching, not the smarter
reasoning that happens in Phase 5's LLM triage layer.
"""

from __future__ import annotations

from payloads import SQL_ERROR_STRINGS, PATH_TRAVERSAL_MARKERS, CMDI_MARKERS, TIMING_BASED_PAYLOADS, TIMING_THRESHOLD_MS


def detect_sqli(payload: str, response_text: str, response_time_ms: int) -> tuple[bool, str]:
    if payload in TIMING_BASED_PAYLOADS and response_time_ms >= TIMING_THRESHOLD_MS:
        return True, f"response delayed {response_time_ms}ms — consistent with SLEEP() payload"

    lower = response_text.lower()
    for err in SQL_ERROR_STRINGS:
        if err in lower:
            return True, f"SQL error string found: '{err}'"

    return False, "no SQL error string or timing anomaly detected"


def detect_xss(payload: str, response_text: str) -> tuple[bool, str]:
    if payload in response_text:
        return True, "payload reflected unescaped in response"
    return False, "payload not found unescaped in response"


def detect_cmdi(response_text: str, baseline_text: str) -> tuple[bool, str]:
    lower = response_text.lower()
    for marker in CMDI_MARKERS:
        if marker in lower and marker not in baseline_text.lower():
            return True, f"command output marker found: '{marker}' (absent in baseline)"
    return False, "no command output markers found beyond baseline"


def detect_path_traversal(response_text: str, baseline_text: str) -> tuple[bool, str]:
    for marker in PATH_TRAVERSAL_MARKERS:
        if marker in response_text and marker not in baseline_text:
            return True, f"file content marker found: '{marker}' (absent in baseline)"
    return False, "no file content markers found beyond baseline"
