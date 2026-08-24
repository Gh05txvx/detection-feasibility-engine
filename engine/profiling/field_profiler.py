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
from typing import Any, Iterable, Mapping, Sequence

import pandas as pd
from pydantic import BaseModel, Field

from engine.ingestion.schemas import LogRecord
from engine.profiling.data_classifier import Classification, DataCategory
from engine.profiling.entity_recognition import EntityType, detect_entity_type

DEFAULT_TOP_N = 5
# Enough events to see a pattern, few enough to read. Raising this makes every
# card and every runbook longer for diminishing evidence.
DEFAULT_EXAMPLE_EVENTS = 5
# Long enough for a URL with a payload in it, short enough not to wreck a table.
EXAMPLE_VALUE_MAX = 160
EXAMPLE_OTHER_FIELDS_MAX = 14

_BOOL_VALUES = {"true", "false", "yes", "no"}
_INT_RE = re.compile(r"^[+-]?\d+$")
_FLOAT_RE = re.compile(r"^[+-]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?$")
_ISO_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?")
_TIME_NAME_RE = re.compile(r"(time|date|timestamp|@timestamp|datetime|epoch)", re.IGNORECASE)
# W3C/IIS, FortiGate and many CSV exports split event time across two columns.
_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIME_ONLY_RE = re.compile(r"^\d{1,2}:\d{2}(:\d{2}(\.\d+)?)?$")
_SECOND_RE = re.compile(r"\d{1,2}:\d{2}:\d{2}")
_MINUTE_RE = re.compile(r"\d{1,2}:\d{2}")
# Sentinel, Excel and most non-ISO CSV exports write the date with separators and
# no fixed component order: `16/07/2026 20:26:12.030`. The four-digit year is
# required, so this cannot swallow an ISO date.
_SLASH_DATE_RE = re.compile(
    r"^(\d{1,2})[/-](\d{1,2})[/-](\d{4})(?:[T ](\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?))?$"
)
# A column that says it is local time and carries no offset. `TimeGenerated
# [Local Time]` is what a Sentinel CSV export writes.
_LOCAL_TIME_RE = re.compile(r"local\s*time", re.IGNORECASE)

# Which component of a separator-separated date is the day. Decided across a
# whole column by _slash_date_order, never from a single value.
DATE_ORDER_DAY_FIRST = "day-first"
DATE_ORDER_MONTH_FIRST = "month-first"
DATE_ORDER_AMBIGUOUS = "ambiguous"
DATE_ORDER_CONTRADICTORY = "contradictory"

_UNREADABLE_DATE_ORDERS = frozenset({DATE_ORDER_AMBIGUOUS, DATE_ORDER_CONTRADICTORY})


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
    # For separator-separated dates only (`16/07/2026`): which component is the
    # day, or that the column does not settle it. None for every other format.
    date_order: str | None = None


class TimestampSource(BaseModel):
    """Where event time comes from: one column, or a date column plus a time column.

    The split form is not an oddity to work around. W3C/IIS *specifies* `date`
    and `time` as separate fields, and that is the format the whole `webserver`
    Sigma taxonomy is written against; FortiGate and many CSV exports do the
    same. Treating it as "no timestamp" makes the engine ask a client to add a
    field they already send.
    """

    field_name: str | None = None
    date_field: str | None = None
    time_field: str | None = None
    granularity: str = "unknown"  # second | minute | day | unknown
    # Set only when the date uses separators rather than ISO order.
    date_order: str | None = None
    # The column says it is local time and carries no UTC offset.
    declares_local_time: bool = False

    @property
    def is_split(self) -> bool:
        return self.date_field is not None and self.time_field is not None

    @property
    def is_readable(self) -> bool:
        """Whether an event time can actually be read out of this column.

        False is not the same as "no timestamp". The field is there and it is a
        timestamp; what is unsettled is which component is the day. The ask for
        the client differs accordingly: confirm a format, not add a field.
        """
        return self.date_order not in _UNREADABLE_DATE_ORDERS

    @property
    def fields(self) -> list[str]:
        if self.is_split:
            return [self.date_field or "", self.time_field or ""]
        return [self.field_name or ""]

    @property
    def description(self) -> str:
        return " + ".join(self.fields)

    @property
    def split_requirement(self) -> str | None:
        """The ask raised by event time arriving spread across two columns."""
        if not self.is_split:
            return None
        return f"combine {self.description} into @timestamp during ingest"

    @property
    def format_requirements(self) -> list[str]:
        """Asks raised by how the time is written, rather than how it is spread."""
        asks: list[str] = []
        if self.date_order == DATE_ORDER_AMBIGUOUS:
            asks.append(
                f"confirm whether the date in {self.description} is day-first or month-first: no "
                "value in the sample has a day above 12, so both readings fit the whole column "
                "and the engine will not guess. Until it is confirmed, the sample has no "
                "measurable time span and alert volume cannot be projected"
            )
        elif self.date_order == DATE_ORDER_CONTRADICTORY:
            asks.append(
                f"re-export {self.description} in ISO-8601: some rows put a value above 12 first "
                "and others put one second, so no single day/month order reads the whole column"
            )
        if self.declares_local_time:
            asks.append(
                f"attach the site's UTC offset to {self.description} during ingest, or convert it "
                "to UTC: the column is labelled local time and carries no offset, so @timestamp "
                "would be wrong by that offset"
            )
        return asks

    @property
    def ingest_requirements(self) -> list[str]:
        """Everything ingest has to settle before this column can drive a rule."""
        split = self.split_requirement
        return ([split] if split else []) + self.format_requirements

    def resolve(self, fields: Mapping[str, Any]) -> datetime | None:
        """Read the event time out of one record."""
        if self.is_split:
            date_value = fields.get(self.date_field or "")
            time_value = fields.get(self.time_field or "")
            if date_value is None or time_value is None:
                return None
            combined = f"{str(date_value).strip()} {str(time_value).strip()}".strip()
            return parse_timestamp(combined, date_order=self.date_order)
        return parse_timestamp(fields.get(self.field_name or ""), date_order=self.date_order)


class EventExample(BaseModel):
    """One sample event, kept so a reviewer can see what a verdict rests on.

    "Matched 5 of 37 events" is a number. The five events are the evidence, and
    a reviewer who cannot see them is being asked to trust the count. The same
    holds on the rejection path, where the events show what the sample *does*
    carry next to the list of what it does not.
    """

    line: int
    # Resolved event time, ISO-8601 UTC. None when the sample has no readable one.
    timestamp: str | None = None
    # The same value exactly as the sample wrote it, so a reader can see the
    # format the engine had to interpret rather than only the interpretation.
    raw_timestamp: str | None = None
    # Fields the verdict turned on, first. Ordered pairs rather than a dict so
    # the order a reviewer reads them in is the order they were declared.
    key_fields: list[tuple[str, str]] = Field(default_factory=list)
    other_fields: list[tuple[str, str]] = Field(default_factory=list)
    omitted_fields: int = 0


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

    def timestamp_source(self) -> TimestampSource | None:
        """How to read event time from a record of this sample, if it is possible."""
        return find_timestamp_source(self.profiles)

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
        present = values.tolist()
        dtype = _infer_dtype(str(column), present)
        profiles.append(
            FieldProfile(
                field_name=str(column),
                dtype=dtype,
                cardinality=int(counts.size),
                null_rate=round(float(blank.mean()), 4),
                entity_type=detect_entity_type(str(column), present),
                top_values=[(str(value), int(count)) for value, count in counts.head(top_n).items()],
                example=str(values.iloc[0]) if not values.empty else None,
                # Decided here rather than in find_timestamp_source, which only
                # sees five sampled values; the order needs the whole column.
                date_order=_slash_date_order(present) if dtype in ("timestamp", "date") else None,
            )
        )

    return profiles


def build_examples(
    records: Sequence[LogRecord],
    *,
    source: TimestampSource | None = None,
    key_fields: Sequence[str] = (),
    limit: int = DEFAULT_EXAMPLE_EVENTS,
) -> list[EventExample]:
    """Keep the first ``limit`` records as reviewable evidence.

    ``key_fields`` are the columns the verdict turned on — the ones a rule
    matched against, or the ones a hypothesis needed. They lead, because the
    reader is checking those specifically; everything else follows as context.

    Blank fields are dropped. On a Cloudflare row most columns are empty, and a
    table of thirty dashes hides the four values that matter.
    """
    time_fields = set(source.fields) if source is not None else set()
    # Event time gets its own column; repeating it as a key field would print the
    # same value twice in every row.
    wanted = list(dict.fromkeys(name for name in key_fields if name and name not in time_fields))

    examples: list[EventExample] = []
    for record in records[:limit]:
        key: list[tuple[str, str]] = []
        for name in wanted:
            value = record.fields.get(name)
            if not _is_blank(value):
                key.append((name, _shorten(value)))

        other: list[tuple[str, str]] = []
        omitted = 0
        for name, value in record.fields.items():
            if name in wanted or name in time_fields or _is_blank(value):
                continue
            if len(other) < EXAMPLE_OTHER_FIELDS_MAX:
                other.append((str(name), _shorten(value)))
            else:
                omitted += 1

        moment = source.resolve(record.fields) if source is not None else None
        examples.append(
            EventExample(
                line=record.line,
                timestamp=moment.isoformat() if moment else None,
                raw_timestamp=_raw_timestamp(record, source),
                key_fields=key,
                other_fields=other,
                omitted_fields=omitted,
            )
        )
    return examples


def _raw_timestamp(record: LogRecord, source: TimestampSource | None) -> str | None:
    """The event time exactly as the sample wrote it, split columns joined."""
    if source is None:
        return None
    parts = [str(record.fields.get(name, "")).strip() for name in source.fields]
    joined = " ".join(part for part in parts if part)
    return joined or None


def _shorten(value: Any) -> str:
    text = str(value).strip()
    return text if len(text) <= EXAMPLE_VALUE_MAX else text[: EXAMPLE_VALUE_MAX - 1] + "…"


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


def parse_timestamp(
    value: Any,
    *,
    allow_date_only: bool = False,
    date_order: str | None = None,
) -> datetime | None:
    """Parse an event timestamp, accepting ISO-8601 and epoch seconds/millis.

    Naive timestamps are read as UTC. Log exports rarely carry an offset, and
    guessing local time would silently shift every window calculation.

    A bare date is refused by default. ``fromisoformat`` happily turns
    ``2026-04-02`` into midnight, which would collapse every event in a
    date-only column onto the same instant and quietly produce a zero-length
    sample span. Callers that genuinely mean a date pass ``allow_date_only``.

    A separator-separated date (``16/07/2026 20:26:12.030``) is read only when
    ``date_order`` says which component is the day. That is a property of the
    column rather than of one value, so it is decided once by
    :func:`_slash_date_order` and passed in; without it the value is refused
    rather than guessed at.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    slash = _SLASH_DATE_RE.match(text)
    if slash is not None:
        return _parse_slash_date(slash, date_order, allow_date_only=allow_date_only)

    if not allow_date_only and _DATE_ONLY_RE.match(text):
        return None

    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        if text.isdigit() and len(text) in (10, 13):
            seconds = int(text) / (1000 if len(text) == 13 else 1)
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        return None

    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _parse_slash_date(
    match: re.Match[str], date_order: str | None, *, allow_date_only: bool
) -> datetime | None:
    """Read one separator-separated date, given the order decided for its column."""
    if date_order == DATE_ORDER_DAY_FIRST:
        day, month = match.group(1), match.group(2)
    elif date_order == DATE_ORDER_MONTH_FIRST:
        month, day = match.group(1), match.group(2)
    else:
        return None

    clock = match.group(4)
    if clock is None and not allow_date_only:
        return None

    text = f"{match.group(3)}-{int(month):02d}-{int(day):02d}"
    if clock:
        hour, _, rest = clock.partition(":")
        text += f" {int(hour):02d}:{rest}"

    try:
        # Constructed without an offset, so the result is always naive: the same
        # read-as-UTC rule the ISO branch applies.
        return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _slash_date_order(values: Sequence[str]) -> str | None:
    """Decide day-first vs month-first across a whole column, or refuse to.

    Never decided from a single value: ``07/06/2026`` fits both readings. It is
    decided from the column, where one day above 12 settles it, and refused when
    the column does not settle it. A wrong guess does not fail loudly — it
    silently moves every event to another date and shifts every window with it.

    Returns None when the values are not separator-separated dates at all.
    """
    first_over_12 = False
    second_over_12 = False
    seen = False

    for value in values:
        match = _SLASH_DATE_RE.match(value.strip())
        if match is None:
            return None
        seen = True
        first_over_12 = first_over_12 or int(match.group(1)) > 12
        second_over_12 = second_over_12 or int(match.group(2)) > 12

    if not seen:
        return None
    if first_over_12 and second_over_12:
        return DATE_ORDER_CONTRADICTORY
    if first_over_12:
        return DATE_ORDER_DAY_FIRST
    if second_over_12:
        return DATE_ORDER_MONTH_FIRST
    return DATE_ORDER_AMBIGUOUS


def find_timestamp_source(profiles: Sequence[FieldProfile]) -> TimestampSource | None:
    """Work out how event time can be read from these fields.

    A single full timestamp wins. Failing that, a date column paired with a
    time column is a complete event time and is treated as one. A lone date or
    a lone time is not: neither can place an event on a timeline, and pretending
    otherwise is how a sample ends up with every event at midnight.
    """
    for profile in profiles:
        if profile.dtype == "timestamp":
            return TimestampSource(
                field_name=profile.field_name,
                granularity=_granularity(profile.example),
                date_order=profile.date_order,
                declares_local_time=_declares_local_time(profile.field_name),
            )

    date_profile = next((profile for profile in profiles if profile.dtype == "date"), None)
    time_profile = next((profile for profile in profiles if profile.dtype == "time"), None)
    if date_profile and time_profile:
        return TimestampSource(
            date_field=date_profile.field_name,
            time_field=time_profile.field_name,
            granularity=_granularity(time_profile.example),
            # The order was decided on the date column; the time column has none.
            date_order=date_profile.date_order,
            declares_local_time=_declares_local_time(date_profile.field_name)
            or _declares_local_time(time_profile.field_name),
        )

    for profile in profiles:
        ecs_name = profile.field_name if profile.is_ecs_compliant else profile.suggested_ecs_field
        if ecs_name == "@timestamp" and profile.dtype == "timestamp":
            return TimestampSource(
                field_name=profile.field_name, granularity=_granularity(profile.example)
            )

    return None


def _granularity(example: str | None) -> str:
    if not example:
        return "unknown"
    if _SECOND_RE.search(example):
        return "second"
    if _MINUTE_RE.search(example):
        return "minute"
    stripped = example.strip()
    if _DATE_ONLY_RE.match(stripped) or _SLASH_DATE_RE.match(stripped):
        return "day"
    return "unknown"


def _declares_local_time(field_name: str | None) -> bool:
    """Whether the column name itself says the times are local and offsetless."""
    return bool(field_name and _LOCAL_TIME_RE.search(field_name))


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
    # A date or a time on its own is not an event timestamp, but a pair of them
    # is. Labelling them distinctly is what lets the pair be recognised.
    if all(_DATE_ONLY_RE.match(value.strip()) for value in values):
        return "date"
    if all(_TIME_ONLY_RE.match(value.strip()) for value in values):
        return "time"
    # A separator-separated date is still a date, whether or not it can be read;
    # calling it a string would make the engine ask a client to add a timestamp
    # field they already send.
    slash_dates = [_SLASH_DATE_RE.match(value.strip()) for value in values]
    if all(match is not None for match in slash_dates):
        return "timestamp" if all(match.group(4) for match in slash_dates) else "date"
    if all(_INT_RE.match(value.strip()) for value in values):
        # A 10 or 13 digit integer in a time-ish field is epoch seconds/millis.
        if _TIME_NAME_RE.search(field_name) and all(len(value.strip()) in (10, 13) for value in values):
            return "timestamp"
        return "integer"
    if all(_FLOAT_RE.match(value.strip()) for value in values):
        return "float"
    return "string"
