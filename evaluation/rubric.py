"""
The automated completeness rubric — implements the 5 criteria from the
proposal's Evaluation Plan (RQ3) exactly as named there.

Two scoring paths:
  - score_llm_report(): scores a TriageVerdict (from triage_output.json)
    against all 5 criteria.
  - score_raw_alert(): scores a raw Finding (from scan_output.json)
    directly, with NO triage applied — representing "the raw output of a
    traditional signature-based scanner" as the proposal's RQ3 puts it.

Some criteria are clean structural checks (1, 2, 5 — presence of a field
is unambiguous). Criteria 3 and 4 require judging text QUALITY
("describes the mechanism," "specific fix vs generic instruction"),
which a fully deterministic rule can only approximate, not judge with
certainty. The proposal itself frames this as "an automated structural
completeness rubric" (not semantic judgment) — the heuristics below stay
true to that framing: they check for structural/lexical signals of
specificity, not full natural-language understanding. This is a real,
worth-stating limitation of any automated (non-LLM-as-judge) rubric.
"""

from __future__ import annotations

from models import RubricScore

MIN_REASONING_LENGTH = 40
MIN_REMEDIATION_LENGTH = 20

# Criterion 3 proxy: reasoning that explains a MECHANISM tends to contain
# causal/mechanistic language, not just a bare assertion.
MECHANISM_INDICATORS = [
    "because", "due to", "which allows", "allowing", "results in", "resulting in",
    "leads to", "leading to", "since the", "as the", "this means", "consequently",
    "confirms", "confirming", "indicates", "indicating", "reflected", "executed",
    "absent in baseline", "present in the response",
]

# Criterion 4 proxy: remediation naming a SPECIFIC technique, not a vague
# instruction. A remediation is scored concrete if it's long enough AND
# mentions at least one specific technique — "sanitize input" alone (no
# specific technique) should NOT pass; "use parameterized queries" should.
SPECIFIC_REMEDIATION_TECHNIQUES = [
    "parameterized quer", "prepared statement", "output encod", "html encod",
    "html-encod", "escape", "allowlist", "allow-list", "whitelist", "content security policy",
    " csp", "subprocess", "avoid shell", "shell=false", "input validation librar",
    "orm", "safe api", "sandboxing", "principle of least privilege", "chroot",
    "path canonicaliz", "realpath", "reject relative path", "prepared statements",
]


def _score_common(
    finding_id: str, source: str, vuln_class: str, endpoint: str, param: str,
    reasoning_text: str, remediation_text: str, has_standard_reference: bool,
) -> RubricScore:
    reasoning_lower = reasoning_text.lower()
    remediation_lower = remediation_text.lower().strip()

    # 1. Vulnerability identification — does the report name the vuln type?
    # vuln_class is a structured field attached to every Finding and every
    # TriageVerdict regardless of source, so this is a clean presence check.
    vulnerability_identification = bool(vuln_class)

    # 2. Location specificity — exact endpoint AND parameter identified.
    location_specificity = bool(endpoint) and bool(param)

    # 3. Exploitability explanation — reasoning describes the MECHANISM,
    # not just asserts a verdict. Proxy: substantive length + at least one
    # mechanism-indicating phrase.
    exploitability_explanation = (
        len(reasoning_text.strip()) >= MIN_REASONING_LENGTH
        and any(term in reasoning_lower for term in MECHANISM_INDICATORS)
    )

    # 4. Concrete remediation step — specific fix, not a generic instruction.
    concrete_remediation_step = (
        len(remediation_lower) >= MIN_REMEDIATION_LENGTH
        and any(term in remediation_lower for term in SPECIFIC_REMEDIATION_TECHNIQUES)
    )

    # 5. Standard reference — CWE ID or OWASP category cited.
    standard_reference = has_standard_reference

    checks = [
        vulnerability_identification, location_specificity, exploitability_explanation,
        concrete_remediation_step, standard_reference,
    ]
    score = sum(checks)  # out of 5, matching the proposal's own scale

    return RubricScore(
        finding_id=finding_id,
        source=source,
        vulnerability_identification=vulnerability_identification,
        location_specificity=location_specificity,
        exploitability_explanation=exploitability_explanation,
        concrete_remediation_step=concrete_remediation_step,
        standard_reference=standard_reference,
        score=score,
    )


def score_llm_report(verdict: dict, finding: dict) -> RubricScore:
    """Scores an LLM-generated triage verdict (from triage_output.json) against all 5 criteria."""
    has_ref = bool(verdict.get("standard_reference", "").strip()) and "no standard classification" not in verdict.get("standard_reference", "").lower()
    return _score_common(
        finding_id=verdict["finding_id"],
        source="llm_report",
        vuln_class=finding.get("vuln_class", ""),
        endpoint=finding.get("endpoint", ""),
        param=finding.get("param", ""),
        reasoning_text=verdict.get("reasoning", ""),
        remediation_text=verdict.get("remediation", ""),
        has_standard_reference=has_ref,
    )


def score_raw_alert(finding: dict) -> RubricScore:
    """
    Scores a raw scanner Finding directly (from scan_output.json), with
    NO LLM triage applied. This is "the raw output of a traditional
    signature-based scanner" per the proposal's RQ3 — expected to score
    low on criteria 3-5, since a signature-based scanner's "evidence"
    field states what pattern matched, not why it's exploitable, and
    carries no remediation or standard-classification field at all.
    """
    return _score_common(
        finding_id=finding["id"],
        source="raw_alert",
        vuln_class=finding.get("vuln_class", ""),
        endpoint=finding.get("endpoint", ""),
        param=finding.get("param", ""),
        reasoning_text=finding.get("evidence", ""),  # a raw alert's only "explanation" is the detection evidence string
        remediation_text="",  # raw scanner findings have no remediation field at all
        has_standard_reference=False,  # raw scanner findings have no CWE/OWASP field at all
    )