from __future__ import annotations

from models import Confidence
from payloads import SQL_ERROR_STRINGS, PATH_TRAVERSAL_MARKERS, CMDI_MARKERS, TIMING_BASED_PAYLOADS, TIMING_THRESHOLD_MS, BOOLEAN_SQLI_INDICATORS, BLOCK_PAGE_INDICATORS


def detect_boolean_sqli_naive(payload: str, response_text: str, baseline_text: str) -> tuple[bool, Confidence, str]:
    length_diff = abs(len(response_text) - len(baseline_text))
    length_ratio = length_diff / max(len(baseline_text), 1)
    if length_ratio > 0.15:
        return True, Confidence.LOW, (
            f"response length changed {length_ratio:.0%} from baseline with no error string "
            f"(naive independent-payload check — no differential or block-page filtering applied)"
        )
    return False, Confidence.LOW, "no significant length change from baseline"


def detect_sqli(payload: str, response_text: str, response_time_ms: int, baseline_text: str = "") -> tuple[bool, Confidence, str]:
    if payload in TIMING_BASED_PAYLOADS and response_time_ms >= TIMING_THRESHOLD_MS:
        return True, Confidence.MEDIUM, f"response delayed {response_time_ms}ms — consistent with SLEEP() payload"

    lower = response_text.lower()
    for err in SQL_ERROR_STRINGS:
        if err in lower:
            return True, Confidence.HIGH, f"SQL error string found: '{err}'"

    return False, Confidence.LOW, "no SQL error string or timing anomaly detected"


def detect_boolean_sqli_pair(
    or_response_text: str, and_response_text: str, baseline_text: str,
    or_payload: str, and_payload: str,
) -> tuple[bool, bool, Confidence, str]:
    or_lower, and_lower = or_response_text.lower(), and_response_text.lower()

    for err in SQL_ERROR_STRINGS:
        if err in or_lower or err in and_lower:
            return True, True, Confidence.HIGH, f"SQL error string found: '{err}'"

    if any(m in or_lower for m in BLOCK_PAGE_INDICATORS) or any(m in and_lower for m in BLOCK_PAGE_INDICATORS):
        return False, False, Confidence.LOW, "response matches a generic block/rejection page, not a data-dependent change"

    or_len, and_len = len(or_response_text), len(and_response_text)
    raw_diff = abs(or_len - and_len)

    payload_len_diff = abs(len(or_payload) - len(and_payload))
    adjusted_diff = max(raw_diff - payload_len_diff, 0)
    adjusted_ratio = adjusted_diff / max(or_len, and_len, 1)

    if adjusted_ratio < 0.05:
        return False, False, Confidence.LOW, (
            f"OR-condition ({or_len} chars) and AND-condition ({and_len} chars) responses "
            f"differ only by about as much as the payloads themselves do — consistent with "
            f"plain reflection, not a data-dependent SQL result"
        )

    baseline_len = len(baseline_text)
    or_diff_from_baseline = abs(or_len - baseline_len) / max(baseline_len, 1)

    if or_diff_from_baseline > 0.10:
        return True, True, Confidence.LOW, (
            f"OR-condition ({or_len} chars) and AND-condition ({and_len} chars) responses "
            f"differ meaningfully from each other (beyond what the payloads' own length "
            f"difference explains) and from baseline ({baseline_len} chars) — "
            f"consistent with boolean-based SQLi (weak signal — needs LLM triage review)"
        )

    return False, False, Confidence.LOW, "OR/AND responses differ from each other but not from baseline — inconclusive"


def detect_xss(payload: str, response_text: str) -> tuple[bool, Confidence, str]:
    if payload in response_text:
        return True, Confidence.HIGH, "payload reflected unescaped in response"
    return False, Confidence.HIGH, "payload not found unescaped in response"


def detect_cmdi(response_text: str, baseline_text: str) -> tuple[bool, Confidence, str]:
    lower = response_text.lower()
    for marker in CMDI_MARKERS:
        if marker in lower and marker not in baseline_text.lower():
            return True, Confidence.HIGH, f"command output marker found: '{marker}' (absent in baseline)"
    return False, Confidence.HIGH, "no command output markers found beyond baseline"


def detect_path_traversal(response_text: str, baseline_text: str) -> tuple[bool, Confidence, str]:
    for marker in PATH_TRAVERSAL_MARKERS:
        if marker in response_text and marker not in baseline_text:
            return True, Confidence.HIGH, f"file content marker found: '{marker}' (absent in baseline)"
    return False, Confidence.HIGH, "no file content markers found beyond baseline"