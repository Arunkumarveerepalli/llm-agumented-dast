"""
Ollama client for LLM triage.

Wraps the ollama Python package: sends the system + user prompt for a
single finding, parses the JSON response, and validates it against the
expected schema. Local models occasionally produce near-JSON (trailing
commas, extra prose despite instructions) — this retries with a stricter
follow-up instruction before giving up, rather than crashing the whole
triage run over one bad response.
"""

from __future__ import annotations

import json
import logging

import ollama

from models import TriageVerdict, Verdict, LLMConfidence
from prompts import SYSTEM_PROMPT, build_user_prompt
from classification import get_standard_reference

logger = logging.getLogger(__name__)

MAX_PARSE_ATTEMPTS = 2


def _strip_json_fences(text: str) -> str:
    """Some models wrap JSON in markdown fences despite instructions not to."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:] if lines[0].startswith("```") else lines
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


def _parse_and_validate(raw_text: str) -> dict:
    cleaned = _strip_json_fences(raw_text)
    data = json.loads(cleaned)  # raises json.JSONDecodeError if malformed — caller handles retry

    required_keys = {"verdict", "llm_confidence", "reasoning", "remediation"}
    missing = required_keys - data.keys()
    if missing:
        raise ValueError(f"Response missing required keys: {missing}")

    if data["verdict"] not in [v.value for v in Verdict]:
        raise ValueError(f"Invalid verdict value: {data['verdict']!r}")
    if data["llm_confidence"] not in [c.value for c in LLMConfidence]:
        raise ValueError(f"Invalid llm_confidence value: {data['llm_confidence']!r}")

    return data


def triage_finding(finding: dict, model: str = "llama3.1:8b") -> TriageVerdict:
    """
    Sends one finding to the local Ollama model and returns a validated
    TriageVerdict. Raises RuntimeError if the model can't produce valid,
    schema-conforming JSON after retries — caller decides whether to
    record that as a triage error and move on.
    """
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_user_prompt(finding)},
    ]

    last_error = None
    for attempt in range(1, MAX_PARSE_ATTEMPTS + 1):
        response = ollama.chat(
            model=model,
            messages=messages,
            format="json",  # constrains output to valid JSON regardless of prompt content
            options={"temperature": 0.1, "num_predict": 300},  # low temperature: judgment task, not creative writing. num_predict caps generation length — this task only needs a short JSON object, no reason to let the model ramble
        )
        raw_text = response["message"]["content"]

        try:
            data = _parse_and_validate(raw_text)
            return TriageVerdict(
                finding_id=finding["id"],
                verdict=Verdict(data["verdict"]),
                llm_confidence=LLMConfidence(data["llm_confidence"]),
                reasoning=data["reasoning"],
                remediation=data["remediation"],
                scanner_confidence=finding["confidence"],
                standard_reference=get_standard_reference(finding["vuln_class"]),
            )
        except (json.JSONDecodeError, ValueError) as exc:
            last_error = exc
            logger.warning(
                "Attempt %d/%d: model produced invalid response for %s: %s",
                attempt, MAX_PARSE_ATTEMPTS, finding["id"], exc,
            )
            messages.append({"role": "assistant", "content": raw_text})
            messages.append({
                "role": "user",
                "content": f"That wasn't valid JSON matching the required schema ({exc}). "
                           f"Respond with ONLY the JSON object, no other text.",
            })

    raise RuntimeError(f"Model failed to produce valid JSON for {finding['id']} after {MAX_PARSE_ATTEMPTS} attempts: {last_error}")