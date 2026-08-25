"""
Data models for the evaluation module.

Implements RQ3's automated completeness rubric EXACTLY as specified in
the proposal's Evaluation Plan: five binary criteria, applied to both
LLM-generated reports and raw scanner alerts, so the mean scores can be
directly compared. This is deterministic, rule-based scoring — not
LLM-as-judge (rejected earlier for circularity).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
import json


@dataclass
class RubricScore:
    """
    The five criteria are named and ordered exactly as in the proposal's
    Evaluation Plan (RQ3 evaluation method):
      1. Vulnerability identification
      2. Location specificity
      3. Exploitability explanation
      4. Concrete remediation step
      5. Standard reference (CWE ID or OWASP category)
    """
    finding_id: str
    source: str  # "llm_report" or "raw_alert" — which side of the RQ3 comparison this score belongs to
    vulnerability_identification: bool
    location_specificity: bool
    exploitability_explanation: bool
    concrete_remediation_step: bool
    standard_reference: bool
    score: float  # out of 5, matching the proposal's "completeness score out of 5"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvalResult:
    target: str
    llm_report_scores: list[RubricScore] = field(default_factory=list)
    raw_alert_scores: list[RubricScore] = field(default_factory=list)
    naive_comparison: dict | None = None

    def add_llm_score(self, score: RubricScore) -> None:
        self.llm_report_scores.append(score)

    def add_raw_score(self, score: RubricScore) -> None:
        self.raw_alert_scores.append(score)

    def _mean(self, scores: list[RubricScore]) -> float:
        if not scores:
            return 0.0
        return round(sum(s.score for s in scores) / len(scores), 3)

    def summary(self) -> dict:
        return {
            "llm_report_mean_completeness": self._mean(self.llm_report_scores),
            "llm_report_count": len(self.llm_report_scores),
            "raw_alert_mean_completeness": self._mean(self.raw_alert_scores),
            "raw_alert_count": len(self.raw_alert_scores),
            "rq3_result": (
                f"LLM-generated reports scored {self._mean(self.llm_report_scores)}/5 on average "
                f"vs raw scanner alerts at {self._mean(self.raw_alert_scores)}/5 — "
                f"{'LLM reports are more complete' if self._mean(self.llm_report_scores) > self._mean(self.raw_alert_scores) else 'no improvement observed'}"
            ),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "target": self.target,
                "summary": self.summary(),
                "llm_report_scores": [s.to_dict() for s in self.llm_report_scores],
                "raw_alert_scores": [s.to_dict() for s in self.raw_alert_scores],
                "naive_comparison": self.naive_comparison,
            },
            indent=indent,
        )

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())