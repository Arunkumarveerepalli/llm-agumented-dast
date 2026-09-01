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
    errors: list[dict] = field(default_factory=list)

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