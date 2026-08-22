"""
Data models for the scanning module.

Mirrors the pattern from recon/models.py: dataclasses define the JSON
contract this module hands to the LLM triage layer. Scanning reads
recon_output.json in, and writes scan_output.json out — no in-memory
wiring between phases.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
import json


class VulnClass(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    PATH_TRAVERSAL = "path_traversal"


@dataclass
class Finding:
    endpoint: str
    param: str
    vuln_class: VulnClass
    payload: str
    detected: bool
    evidence: str
    response_snippet: str
    response_time_ms: int
    baseline_length: int
    response_length: int

    def to_dict(self) -> dict:
        d = asdict(self)
        d["vuln_class"] = self.vuln_class.value
        return d


@dataclass
class ScanResult:
    target: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "target": self.target,
                "findings": [f.to_dict() for f in self.findings],
            },
            indent=indent,
        )

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())