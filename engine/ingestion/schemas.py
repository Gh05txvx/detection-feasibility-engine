"""Schemas produced by the ingestion layer (docs/BLUEPRINT.md 5.1)."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SampleFormat(str, Enum):
    """Shapes a pre-onboarding sample arrives in."""

    CSV = "csv"
    JSON = "json"
    JSONL = "jsonl"
    # An Elasticsearch _search response saved to disk, i.e. the second input
    # scenario in BLUEPRINT 5.1: a live index exported before it was normalized.
    ELASTIC_RESPONSE = "elastic_response"


class LogRecord(BaseModel):
    """One parsed event.

    ``fields`` holds the values profiling and matching work against, already
    normalized (nested objects flattened to dotted keys, URL-encoded values
    decoded). ``raw_fields`` keeps the pre-normalization text for any field
    normalization actually changed, so nothing is silently rewritten.
    """

    line: int
    fields: dict[str, Any]
    raw_fields: dict[str, str] = Field(default_factory=dict)

    def get(self, name: str, default: Any = None) -> Any:
        return self.fields.get(name, default)


class ParsedSample(BaseModel):
    """A whole sample file, plus what parsing it revealed."""

    path: str
    format: SampleFormat
    encoding: str
    delimiter: str | None = None
    records: list[LogRecord] = Field(default_factory=list)
    # Union of every key seen, in first-seen order, so output stays stable and
    # column order survives from the source file.
    field_names: list[str] = Field(default_factory=list)
    # Records that could not be parsed, capped. Reported, never swallowed.
    problems: list[str] = Field(default_factory=list)
    truncated: bool = False

    @property
    def record_count(self) -> int:
        return len(self.records)
