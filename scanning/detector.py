"""
Signature-based detection, one function per vuln class.

Each detector returns (detected: bool, confidence: Confidence, evidence: str).
Confidence reflects how direct the detection mechanism is — see
models.Confidence's docstring for the HIGH/MEDIUM/LOW definitions. This is
the "first pass" — deliberately simple pattern matching, not the smarter
reasoning that happens in Phase 5's LLM triage layer. Confidence exists so
that layer can weigh findings instead of treating every "detected: true"
the same.
"""

from __future__ import annotations

from models import Confidence
from payloads import SQL_ERROR_STRINGS, PATH_TRAVERSAL_MARKERS, CMDI_MARKERS, TIMING_BASED_PAYLOADS, TIMING_THRESHOLD_MS, BOOLEAN_SQLI_INDICATORS, BLOCK_PAGE_INDICATORS


def detect_sqli(payload: str, response_text: str, response_time_ms: int, baseline_text: str = "") -> tuple[bool, Confidence, str]:
    if payload in TIMING_BASED_PAYLOADS and response_time_ms >= TIMING_THRESHOLD_MS:
        return True, Confidence.MEDIUM, f"response delayed {response_time_ms}ms — consistent with SLEEP() payload"

    lower = response_text.lower()
    for err in SQL_ERROR_STRINGS:
        if err in lower:
            return True, Confidence.HIGH, f"SQL error string found: '{err}'"

    # Boolean-based indicator payloads are handled separately by
    # detect_boolean_sqli_pair — they need each other, not just baseline,
    # to be judged reliably. See that function's docstring for why.
    return False, Confidence.LOW, "no SQL error string or timing anomaly detected"


def detect_boolean_sqli_pair(
    or_response_text: str, and_response_text: str, baseline_text: str,
    or_payload: str, and_payload: str,
) -> tuple[bool, bool, Confidence, str]:
    """
    Judges the classic 'OR 1=1' (always-true) vs 'AND 1=2' (always-false)
    payload pair together, not independently.

    Why together: both payloads are syntactically valid SQL, so neither
    triggers an error on its own. If the app is genuinely running them as
    SQL, a true condition and a false condition should return visibly
    different amounts of data. If the app ISN'T running them as SQL — e.g.
    the param actually selects a file, and an invalid value just falls
    back to a generic page — both payloads tend to produce the SAME
    output, since the fallback doesn't depend on the payload's logical
    truth value at all. Comparing each to baseline alone can't catch that
    distinction; comparing them to EACH OTHER can.

    Two things this also has to guard against, found via testing:
      1. A genuine SQL error can still occur for either payload (quoting
         differs across DB engines/contexts) — checked first, same as
         detect_sqli, so this doesn't lose that signal.
      2. On any page that reflects its input directly (e.g. an XSS-prone
         field), the OR and AND payloads are naturally different STRING
         LENGTHS (11 vs 13 chars), so their reflected responses differ in
         length even with zero SQL involvement. We subtract that expected
         reflection-driven difference before judging whether the
         remaining gap is meaningful.

    Confidence is always LOW for a positive result here (even the
    strongest case this function can detect is still an inference from
    response shape, not a direct marker) — UNLESS an outright SQL error
    string is found, which is HIGH regardless of which payload triggered it.

    Returns (or_detected, and_detected, confidence, shared_evidence).
    """
    or_lower, and_lower = or_response_text.lower(), and_response_text.lower()

    for err in SQL_ERROR_STRINGS:
        if err in or_lower or err in and_lower:
            return True, True, Confidence.HIGH, f"SQL error string found: '{err}'"

    if any(m in or_lower for m in BLOCK_PAGE_INDICATORS) or any(m in and_lower for m in BLOCK_PAGE_INDICATORS):
        return False, False, Confidence.LOW, "response matches a generic block/rejection page, not a data-dependent change"

    or_len, and_len = len(or_response_text), len(and_response_text)
    raw_diff = abs(or_len - and_len)

    # If the two payloads are simply reflected verbatim, their own length
    # difference explains most of the response difference — subtract it
    # out before judging whether real row-count variation remains.
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

    return False, False, Confidence.LOW, (
        "OR/AND responses differ from each other but not from baseline — inconclusive"
    )


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