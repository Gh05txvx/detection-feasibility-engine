"""The result type of feasibility matching (docs/BLUEPRINT.md 5.3)."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class MatchSource(str, Enum):
    SIGMA = "sigma"
    INTERNAL_TAXONOMY = "internal_taxonomy"


class MatchCandidate(BaseModel):
    """A rule that could plausibly be built from this sample.

    Beyond the four fields the pipeline strictly needs, a candidate carries the
    evidence behind its score. docs/BLUEPRINT.md §3 requires every match *and*
    every reject to record reasoning rather than a bare number, and a confidence
    float on its own cannot be reviewed by the analyst who has to sign it off.
    """

    source: MatchSource
    rule_ref: str
    confidence: float
    mitre_techniques: list[str] = Field(default_factory=list)

    title: str = ""
    level: str | None = None
    rule_path: str | None = None
    logsource: dict[str, str | None] = Field(default_factory=dict)
    # Sigma field name -> the sample field that satisfies it.
    matched_fields: dict[str, str] = Field(default_factory=dict)
    missing_fields: list[str] = Field(default_factory=list)
    uses_full_text_search: bool = False
    # Preconditions the detection logic depends on. Carried up from an internal
    # taxonomy entry, because they are review items, not footnotes.
    assumptions: list[str] = Field(default_factory=list)
    reasoning: str = ""

    @property
    def field_coverage(self) -> float:
        total = len(self.matched_fields) + len(self.missing_fields)
        return 1.0 if total == 0 else len(self.matched_fields) / total
