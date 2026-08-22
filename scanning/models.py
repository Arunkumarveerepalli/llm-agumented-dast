"""
Data models for the scanning module.

Mirrors the pattern from recon/models.py: dataclasses define the JSON
contract this module hands to the LLM triage layer. Scanning reads
recon_output.json in, and writes scan_output.json out — no in-memory
wiring between phases.

Design choices made after reviewing real scan output against DVWA:
  - Only DETECTED findings are serialized. Out of 318 test cases in a
    real run, only ~10 were genuine detections — writing all 318 to disk
    added noise without adding value; a "no vulnerability found" result
    isn't something the LLM triage layer needs to reason about. Totals
    are preserved in the summary block instead, so the methodology is
    still fully auditable without the dead weight.
  - Confidence is explicit, not implied by evidence wording, so the LLM
    triage layer can weigh findings programmatically instead of parsing
    prose.
  - Each finding gets a short stable ID so triage output can reference
    "F003" instead of repeating the full endpoint/param/payload each time.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import Counter
import json


class VulnClass(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    PATH_TRAVERSAL = "path_traversal"


class Confidence(str, Enum):
    """
    How much weight the detector itself puts behind a finding, based on
    which detection mechanism fired — not a probability, just a signal
    for the LLM triage layer to weigh accordingly rather than treating
    every finding as equally trustworthy.

    HIGH:   a direct, unambiguous signature — an SQL error string,
            a command-output marker, a file-content marker, or a payload
            reflected verbatim and unescaped.
    MEDIUM: a real but indirect signal — response timing consistent with
            an injected delay, which can in principle be affected by
            network jitter or server load even though a 10s delay
            against a 2s SLEEP is a strong indicator in practice.
    LOW:    an inferred signal from response-shape comparison rather than
            a direct marker — e.g. the boolean-based SQLi differential
            check. Real, but the weakest category by construction.
    """
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    id: str
    endpoint: str
    param: str
    vuln_class: VulnClass
    confidence: Confidence
    payload: str
    evidence: str
    response_snippet: str
    response_time_ms: int
    baseline_length: int
    response_length: int

    def to_dict(self) -> dict:
        d = asdict(self)
        d["vuln_class"] = self.vuln_class.value
        d["confidence"] = self.confidence.value
        return d


@dataclass
class ScanResult:
    target: str
    total_tests_run: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)  # {"endpoint": ..., "error": ...} — endpoints that failed entirely, so gaps in coverage are visible in the output itself, not just console logs

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, endpoint: str, error: str) -> None:
        self.errors.append({"endpoint": endpoint, "error": error})

    def _next_id(self) -> str:
        return f"F{len(self.findings) + 1:03d}"

    def summary(self) -> dict:
        by_class = Counter(f.vuln_class.value for f in self.findings)
        by_confidence = Counter(f.confidence.value for f in self.findings)
        return {
            "total_tests_run": self.total_tests_run,
            "findings_count": len(self.findings),
            "by_vuln_class": dict(by_class),
            "by_confidence": dict(by_confidence),
            "endpoints_failed": len(self.errors),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "target": self.target,
                "summary": self.summary(),
                "findings": [f.to_dict() for f in self.findings],
                "errors": self.errors,
            },
            indent=indent,
        )

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())