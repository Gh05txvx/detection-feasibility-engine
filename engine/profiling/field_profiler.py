"""Per-field statistics and the assembled log fingerprint (docs/BLUEPRINT.md 5.2).

One deliberate non-behaviour: nothing here drops or down-ranks a field for having
a high null rate. On the Phase 0 fixture, `RuleID`, `ClientRequestQuery`, and
`OriginResponseStatus` are all empty on most rows, and in each case the emptiness
is the signal (no WAF rule fired, no query string, blocked before it reached the
origin). Treating "mostly empty" as "low value" would throw away the fields that
carry the detection. See docs/phase0-smoke-test.md §9.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

import pandas as pd
from pydantic import BaseModel, Field

from engine.ingestion.schemas import LogRecord
from engine.profiling.data_classifier import Classification, DataCategory
from engine.profiling.entity_recognition import EntityType, detect_entity_type

DEFAULT_TOP_N = 5

_BOOL_VALUES = {"true", "false", "yes", "no"}
_INT_RE = re.compile(r"^[+-]?\d+$")
_FLOAT_RE = re.compile(r"^[+-]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?$")
_ISO_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?")
_TIME_NAME_RE = re.compile(r"(time|date|timestamp|@timestamp|datetime|epoch)", re.IGNORECASE)


class FieldProfile(BaseModel):
    """Statistics and labels for one field."""

    field_name: str
    dtype: str
    cardinality: int
    null_rate: float
    entity_type: EntityType | None = None
    is_ecs_compliant: bool = False
    suggested_ecs_field: str | None = None
    # BLUEPRINT 5.2 asks for value distribution, not just cardinality; these two
    # are what make a profile reviewable by a human.
    top_values: list[tuple[str, int]] = Field(default_factory=list)
    example: str | None = None


class LogFingerprint(BaseModel):
    """What the sample is, structurally: the input to matching."""

    profiles: list[FieldProfile] = Field(default_factory=list)
    inferred_category: str | None = None   # analog to Sigma logsource.category
    inferred_product: str | None = None    # analog to Sigma logsource.product
    inferred_service: str | None = None    # analog to Sigma logsource.service
    data_category: DataCategory | None = None
    official_integration_available: bool = False
    official_integration_name: str | None = None
    record_count: int = 0
    classification_confidence: float = 0.0
    classification_evidence: list[str] = Field(default_factory=list)

    @property
    def field_names(self) -> list[str]:
        return [profile.field_name for profile in self.profiles]

    def profile_for(self, field_name: str) -> FieldProfile | None:
        for profile in self.profiles:
            if profile.field_name == field_name:
                return profile
        return None

    def timestamp_profile(self) -> FieldProfile | None:
        """The field carrying event time, by inferred type first, ECS name second."""
        for profile in self.profiles:
            if profile.dtype == "timestamp":
                return profile
        for profile in self.profiles:
            ecs_name = profile.field_name if profile.is_ecs_compliant else profile.suggested_ecs_field
            if ecs_name == "@timestamp":
                return profile
        return None

    def resolvable_names(self) -> dict[str, str]:
        """Every lowercased name this sample answers to -> the field providing it.

        Includes each raw field name, its last dotted segment, and the ECS field
        it maps to. This is what lets a rule written in ECS terms and a taxonomy
        entry written in vendor terms both resolve against the same sample.
        """
        names: dict[str, str] = {}
        for profile in self.profiles:
            name = profile.field_name
            names.setdefault(name.lower(), name)
            if "." in name:
                names.setdefault(name.rsplit(".", 1)[-1].lower(), name)
            ecs_field = name if profile.is_ecs_compliant else profile.suggested_ecs_field
            if ecs_field:
                names.setdefault(ecs_field.lower(), name)
                names.setdefault(ecs_field.rsplit(".", 1)[-1].lower(), name)
        return names


def profile_fields(
    records: Sequence[LogRecord],
    *,
    field_names: Sequence[str] | None = None,
    top_n: int = DEFAULT_TOP_N,
) -> list[FieldProfile]:
    """Compute a profile for every field present in the records."""
    if not records:
        return []

    frame = pd.DataFrame([record.fields for record in records], dtype=object)
    if frame.empty:
        return []

    columns = _ordered_columns(frame.columns, field_names)
    profiles: list[FieldProfile] = []

    for column in columns:
        series = frame[column]
        blank = series.map(_is_blank)
        # astype(str) on an object column keeps ints as "8812"; letting pandas
        # infer numeric dtypes first would turn them into "8812.0".
        values = series[~blank].astype(str)

        counts = values.value_counts()
        profiles.append(
            FieldProfile(
                field_name=str(column),
                dtype=_infer_dtype(str(column), values.tolist()),
                cardinality=int(counts.size),
                null_rate=round(float(blank.mean()), 4),
                entity_type=detect_entity_type(str(column), values.tolist()),
                top_values=[(str(value), int(count)) for value, count in counts.head(top_n).items()],
                example=str(values.iloc[0]) if not values.empty else None,
            )
        )

    return profiles


def build_fingerprint(
    profiles: Sequence[FieldProfile],
    classification: Classification,
    *,
    record_count: int = 0,
    integration_name: str | None = None,
) -> LogFingerprint:
    """Assemble the fingerprint from the profiling and classification results."""
    return LogFingerprint(
        profiles=list(profiles),
        inferred_category=classification.inferred_category,
        inferred_product=classification.inferred_product,
        inferred_service=classification.inferred_service,
        data_category=classification.data_category,
        official_integration_available=integration_name is not None,
        official_integration_name=integration_name,
        record_count=record_count,
        classification_confidence=classification.confidence,
        classification_evidence=list(classification.evidence),
    )


def parse_timestamp(value: Any) -> datetime | None:
    """Parse an event timestamp, accepting ISO-8601 and epoch seconds/millis.

    Naive timestamps are read as UTC. Log exports rarely carry an offset, and
    guessing local time would silently shift every window calculation.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        if text.isdigit() and len(text) in (10, 13):
            seconds = int(text) / (1000 if len(text) == 13 else 1)
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        return None

    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _ordered_columns(columns: Iterable[Any], field_names: Sequence[str] | None) -> list[Any]:
    """Keep the source file's column order, appending anything it did not list."""
    available = list(columns)
    if not field_names:
        return available
    known = [name for name in field_names if name in available]
    extra = [name for name in available if name not in set(known)]
    return known + extra


# Placeholders log exporters write instead of leaving a cell empty. Deliberately
# short: "unknown" and "none" are excluded because they are real values in some
# sources (Cloudflare writes Source=unknown for events no WAF rule produced).
_NULL_PLACEHOLDERS = frozenset({"-", "--", "n/a", "null", "(none)"})


def _is_blank(value: Any) -> bool:
    """Treat None, NaN, empty strings, and null placeholders alike."""
    if value is None:
        return True
    if isinstance(value, float) and pd.isna(value):
        return True
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    return not stripped or stripped.lower() in _NULL_PLACEHOLDERS


def _infer_dtype(field_name: str, values: Sequence[str]) -> str:
    if not values:
        return "empty"

    if all(value.strip().lower() in _BOOL_VALUES for value in values):
        return "boolean"
    if all(_ISO_TIME_RE.match(value.strip()) for value in values):
        return "timestamp"
    if all(_INT_RE.match(value.strip()) for value in values):
        # A 10 or 13 digit integer in a time-ish field is epoch seconds/millis.
        if _TIME_NAME_RE.search(field_name) and all(len(value.strip()) in (10, 13) for value in values):
            return "timestamp"
        return "integer"
    if all(_FLOAT_RE.match(value.strip()) for value in values):
        return "float"
    return "string"
