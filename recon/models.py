"""
Data models for the recon module.

These classes define the contract between recon and the scanning module.
Recon populates a ReconResult; the scanner reads it back from JSON and
never talks to the live target except through this structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
import json


class ParamSource(str, Enum):
    QUERY = "query"
    FORM = "form"


@dataclass
class Param:
    name: str
    source: ParamSource
    type: str = "string"          # reserved for future use (int, string, file, ...)
    default_value: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["source"] = self.source.value
        return d


@dataclass
class FormSpec:
    action: str
    method: str                    # "GET" or "POST"
    inputs: list[Param] = field(default_factory=list)
    has_csrf_token: bool = False
    csrf_field_name: str | None = None
    requires_auth: bool = True     # assume auth required unless proven otherwise
    submit_fields: dict[str, str] = field(default_factory=dict)  # e.g. {"Submit": "Submit"} — sent as-is on every request, never fuzzed; many apps only run their query if the submit field is present

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "method": self.method,
            "inputs": [p.to_dict() for p in self.inputs],
            "has_csrf_token": self.has_csrf_token,
            "csrf_field_name": self.csrf_field_name,
            "requires_auth": self.requires_auth,
            "submit_fields": self.submit_fields,
        }


@dataclass
class Endpoint:
    url: str
    method: str                    # "GET" or "POST" — GET for query-param pages, POST if reached via form
    params: list[Param] = field(default_factory=list)
    form: FormSpec | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": [p.to_dict() for p in self.params],
            "form": self.form.to_dict() if self.form else None,
        }

    def dedup_key(self) -> tuple:
        """Key used by the crawler to avoid storing duplicate endpoints."""
        param_names = tuple(sorted(p.name for p in self.params))
        return (self.url, self.method, param_names)


@dataclass
class ReconResult:
    target: str
    endpoints: list[Endpoint] = field(default_factory=list)

    def add(self, endpoint: Endpoint) -> None:
        self.endpoints.append(endpoint)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            {
                "target": self.target,
                "endpoints": [e.to_dict() for e in self.endpoints],
            },
            indent=indent,
        )

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())