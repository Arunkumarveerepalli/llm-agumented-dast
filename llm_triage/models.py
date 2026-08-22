"""
Data models for the LLM triage module.

Reads scan_output.json (Finding objects from the scanning module) and
produces triage_output.json — one TriageVerdict per Finding, pairing the
scanner's own structural confidence with the LLM's independent judgment.
That pairing is itself useful data for RQ3: does the LLM agree with the
scanner's confidence level, and where does it disagree?
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
import json


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class LLMConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TriageVerdict:
    finding_id: str                # matches Finding.id from scan_output.json, e.g. "F001"
    verdict: Verdict
    llm_confidence: LLMConfidence
    reasoning: str
    remediation: str
    scanner_confidence: str        # copied from the original Finding, for easy side-by-side comparison

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["llm_confidence"] = self.llm_confidence.value
        return d


@dataclass
class TriageResult:
    target: str
    model_used: str
    verdicts: list[TriageVerdict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)  # {"finding_id": ..., "error": ...}

    def add(self, verdict: TriageVerdict) -> None:
        self.verdicts.append(verdict)

    def add_error(self, finding_id: str, error: str) -> None:
        self.errors.append({"finding_id": finding_id, "error": error})

    def summary(self) -> dict:
        from collections import Counter
        by_verdict = Counter(v.verdict.value for v in self.verdicts)
        return {
            "total_findings_triaged": len(self.verdicts),
            "by_verdict": dict(by_verdict),
            "triage_errors": len(self.errors),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "target": self.target,
                "model_used": self.model_used,
                "summary": self.summary(),
                "verdicts": [v.to_dict() for v in self.verdicts],
                "errors": self.errors,
            },
            indent=indent,
        )

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())