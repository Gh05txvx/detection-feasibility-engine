"""Turn one sample's ECS gap analysis into two objects Elastic can apply.

BLUEPRINT 5.1 says the field inventory is "input awal buat desain index
template/pipeline yang akan dibangun di fase implementation". This module is that
inventory written in the form the implementation actually consumes:

* an **ingest pipeline** that renames every field the sample carries to the ECS
  field the gap analysis resolved for it, and
* a **composable index template** that types the result, so `source.ip` is
  indexed as `ip` and `source.port` as `long` rather than as whatever dynamic
  mapping guesses from a CSV string.

Both are ordinary Elasticsearch API bodies: `PUT _ingest/pipeline/<id>` and
`PUT _index_template/<id>`. Neither is ever sent anywhere from here - the tool
stays offline, and BLUEPRINT 5.8 puts a human between any output and Elastic.
The download is the handover, not a deployment.

Three decisions worth stating, because each could reasonably have gone the other
way:

* **Fields with no ECS home are namespaced, not left alone.** `ClientRequestPath`
  becomes `cloudflare.client_request_path`. Leaving vendor names at the root is
  what ECS's own guidance warns against: a later ECS release can claim the name,
  and the index then holds two incompatible meanings for it. Moving leftovers
  into a vendor namespace is what every official integration does.
* **The original of anything rewritten is preserved**, under that same namespace
  and always as `keyword`. A timestamp column read into `@timestamp` is still the
  only record of the text that was parsed; if the parse turns out to be wrong by
  a timezone, the original is what fixes it.
* **Event time is never guessed.** When the profiler could not settle how a
  column's date reads, no `date` processor is written at all and the reason is
  stated in `_meta.review_before_deploy`. A pipeline that silently mis-dates
  every event is worse than one that visibly lacks a step.
"""

from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, Field

from engine.profiling import ecs_gap
from engine.profiling.ecs_gap import ECS_ROOTS, ECS_SCALARS, EcsGapReport
from engine.profiling.field_profiler import (
    DATE_ORDER_DAY_FIRST,
    DATE_ORDER_MONTH_FIRST,
    NULL_PLACEHOLDERS,
    SLASH_DATE_RE,
    FieldProfile,
    LogFingerprint,
    TimestampSource,
)

# Stamped onto every document so a reader can tell which ECS revision these
# field names were resolved against.
ECS_VERSION = "8.11.0"

# Elastic's own `logs` index template sits at priority 100; anything meant to win
# over it has to be higher. The official integrations ship theirs at 200.
TEMPLATE_PRIORITY = 200

# Scratch object the split-timestamp join writes into, removed before the
# document is indexed. `_tmp` is the name elastic/integrations pipelines use for
# exactly this.
TMP_ROOT = "_tmp"
TMP_EVENT_TIME = f"{TMP_ROOT}.event_time"

FAILURE_TAG = "_ecs_normalization_failed"

# Field names that can be referenced from a Mustache template and a Painless
# condition. A name with a space or a brace is safe in neither, and such a field
# gets a review note instead of a processor that would fail at ingest.
_REFERENCEABLE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")

_ISO_T_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T")
_ISO_SPACE_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{1,2}:\d{2}")
_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_LEADING_ZERO_RE = re.compile(r"^0\d")

# ECS field types that do not follow from the profiled dtype.
_EXACT_TYPES = {
    "@timestamp": "date",
    "message": "match_only_text",
    "error.message": "match_only_text",
    "tags": "keyword",
    "ecs.version": "keyword",
    "event.created": "date",
    "event.start": "date",
    "event.end": "date",
    "event.ingested": "date",
    "event.duration": "long",
}
# Checked in order, so a longer tail wins over a shorter one it contains.
_SUFFIX_TYPES: tuple[tuple[str, str], ...] = (
    (".as.number", "long"),
    (".status_code", "long"),
    (".ip", "ip"),
    (".port", "long"),
    (".bytes", "long"),
    (".packets", "long"),
)
_DTYPE_TYPES = {"integer": "long", "float": "double", "boolean": "boolean"}
# Types worth a `convert` processor. `ip` is left to the index template: the
# mapping parses the string on its own, and one fewer processor is one fewer
# thing that can differ between an 8.x minor and the one the client runs.
_CONVERTED_TYPES = frozenset({"long", "double", "boolean"})

# Blank cells have to go before anything typed sees them: `source.ip` mapped as
# `ip` rejects the empty string, and a W3C log writes `-` in every field it has
# no value for. Same placeholder list the profiler counts as empty, so what the
# Structure page called blank is what the pipeline drops.
_DROP_BLANK_SOURCE = (
    "for (def path : params.fields) {"
    " def parts = path.splitOnToken('.'); def node = ctx;"
    " for (int i = 0; i < parts.length - 1; i++) {"
    " if (!(node instanceof Map)) { node = null; break; } node = node[parts[i]]; }"
    " if (!(node instanceof Map)) { continue; }"
    " def leaf = parts[parts.length - 1]; def value = node[leaf];"
    " if (!(value instanceof String)) { continue; }"
    " def text = ((String) value).trim();"
    " if (text.isEmpty() || params.blanks.contains(text.toLowerCase())) { node.remove(leaf); } }"
)


class MappingOrigin(str, Enum):
    """Where a field's ECS target came from, which is how much it is worth."""

    ECS = "already-ecs"
    INTEGRATION = "official-integration"
    HEURISTIC = "heuristic"
    TIMESTAMP = "event-time"
    CUSTOM = "vendor-namespace"


class FieldMapping(BaseModel):
    """One field of the sample, and what the pipeline does with it."""

    source_field: str
    target_field: str
    es_type: str
    origin: MappingOrigin
    # Where the untouched original ends up, when the field is *read into* an ECS
    # target rather than moved into one. None means the rename is the whole story.
    kept_as: str | None = None
    note: str | None = None

    @property
    def renamed(self) -> bool:
        return self.source_field != self.target_field


class EcsExport(BaseModel):
    """The deployable form of one sample's ECS gap analysis."""

    dataset: str
    namespace: str
    pipeline_id: str
    template_id: str
    index_pattern: str
    mappings: list[FieldMapping] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    review: list[str] = Field(default_factory=list)
    ingest_pipeline: dict[str, Any] = Field(default_factory=dict)
    index_template: dict[str, Any] = Field(default_factory=dict)

    @property
    def to_ecs(self) -> int:
        """Fields that land on a real ECS field, however they got there."""
        return len(self.mappings) - self.to_namespace

    @property
    def to_namespace(self) -> int:
        """Fields ECS has no home for, moved under the vendor namespace."""
        return sum(1 for mapping in self.mappings if mapping.origin is MappingOrigin.CUSTOM)

    @property
    def pipeline_json(self) -> str:
        return json.dumps(self.ingest_pipeline, indent=2, ensure_ascii=False) + "\n"

    @property
    def template_json(self) -> str:
        return json.dumps(self.index_template, indent=2, ensure_ascii=False) + "\n"

    @property
    def pipeline_filename(self) -> str:
        return f"{self.pipeline_id}.json"

    @property
    def template_filename(self) -> str:
        return f"{self.template_id}-index-template.json"


# ---------------------------------------------------------------------- build


def build(
    fingerprint: LogFingerprint,
    gap: EcsGapReport,
    *,
    sample_name: str = "",
) -> EcsExport:
    """Plan the normalization for one sample and render both API bodies."""
    module, dataset = _dataset_name(fingerprint, sample_name)
    namespace = _namespace(module)
    pipeline_id = f"logs-{dataset}-ecs-normalization"
    template_id = f"logs-{dataset}"
    index_pattern = f"logs-{dataset}-*"

    source = fingerprint.timestamp_source()
    conflicts: list[str] = []
    mappings = _plan(fingerprint.profiles, gap, source, namespace, conflicts)

    review: list[str] = []
    processors = _processors(
        fingerprint,
        mappings,
        source,
        dataset,
        module,
        review,
        named=bool(fingerprint.inferred_product or fingerprint.inferred_category),
    )
    _review_notes(review, fingerprint, gap, mappings, conflicts)

    meta = {
        "generated_by": "Detection Feasibility & Rule Recommendation Engine",
        "sample": sample_name or "unknown",
        "log_source": _log_source(fingerprint),
        "official_integration": gap.integration.name if gap.integration else None,
        "ecs_version": ECS_VERSION,
        "field_mapping": {mapping.source_field: mapping.target_field for mapping in mappings},
        "kept_under_vendor_namespace": sorted(
            mapping.target_field for mapping in mappings if mapping.origin is MappingOrigin.CUSTOM
        ),
        "review_before_deploy": review,
        "conflicts": conflicts,
        "not_deployed": "Generated offline for review. Nothing here was applied to Elastic.",
    }

    pipeline = {
        "description": (
            f"ECS normalization for {_log_source(fingerprint)}, drafted from the sample "
            f"{sample_name or 'provided'}. Review before deploying."
        ),
        "processors": processors,
        "on_failure": [
            {"set": {"field": "error.message", "value": "{{{_ingest.on_failure_message}}}"}},
            {"append": {"field": "tags", "value": FAILURE_TAG}},
        ],
        "_meta": meta,
    }

    template = {
        "index_patterns": [index_pattern],
        "data_stream": {},
        "priority": TEMPLATE_PRIORITY,
        "template": {
            "settings": {"index.default_pipeline": pipeline_id},
            "mappings": {
                # A log field that happens to hold a date-shaped string should
                # stay a string; only the column the pipeline parsed is a date.
                "date_detection": False,
                "properties": _properties(mappings),
            },
        },
        "_meta": meta,
    }

    return EcsExport(
        dataset=dataset,
        namespace=namespace,
        pipeline_id=pipeline_id,
        template_id=template_id,
        index_pattern=index_pattern,
        mappings=mappings,
        conflicts=conflicts,
        review=review,
        ingest_pipeline=pipeline,
        index_template=template,
    )


def write(export: EcsExport, out_dir: str | Path) -> list[Path]:
    """Write both bodies into `out_dir` and return where they went.

    Named after the id each one is applied under, so a directory holding several
    samples' output stays readable and a second run of the same source overwrites
    rather than accumulating.
    """
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)

    pipeline_path = directory / export.pipeline_filename
    template_path = directory / export.template_filename
    pipeline_path.write_text(export.pipeline_json, encoding="utf-8")
    template_path.write_text(export.template_json, encoding="utf-8")
    return [pipeline_path, template_path]


# ------------------------------------------------------------------- the plan


def _plan(
    profiles: Sequence[FieldProfile],
    gap: EcsGapReport,
    source: TimestampSource | None,
    namespace: str,
    conflicts: list[str],
) -> list[FieldMapping]:
    """Decide, for every field in the sample's own order, where it ends up."""
    time_fields = set(source.fields) if source is not None else set()
    claimed: dict[str, str] = {}

    def claim(target: str, owner: str) -> str | None:
        """Take a target for one field, or report that another field holds it."""
        holder = claimed.get(target)
        if holder is not None and holder != owner:
            conflicts.append(
                f"'{owner}' also resolves to '{target}', which '{holder}' already takes; "
                f"'{owner}' is kept under the vendor namespace instead"
            )
            return None
        claimed[target] = owner
        return target

    def keep(name: str) -> str:
        """A free namespaced home for the original text of `name`."""
        base = _custom_target(namespace, name)
        candidate, suffix = base, 1
        while claimed.get(candidate, name) != name:
            suffix += 1
            candidate = f"{base}_{suffix}"
        claimed[candidate] = name
        return candidate

    mappings: list[FieldMapping] = []
    for profile in profiles:
        name = profile.field_name

        if name in time_fields:
            mappings.append(
                FieldMapping(
                    source_field=name,
                    target_field="@timestamp",
                    es_type="date",
                    origin=MappingOrigin.TIMESTAMP,
                    kept_as=keep(name),
                    note="read into @timestamp by the date processor; the original text is kept",
                )
            )
            continue

        target, origin, note = _ecs_target(profile, gap)

        if target and target.startswith("related.") and _REFERENCEABLE_NAME.match(name):
            # ECS declares `related.*` as arrays precisely so several fields can
            # feed one. A rename would have the last IP field silently overwrite
            # the first; appending keeps both, and the original stays under the
            # namespace so the value is still attributable to its column.
            claimed.setdefault(target, name)
            mappings.append(
                FieldMapping(
                    source_field=name,
                    target_field=target,
                    es_type=_es_type(target, profile),
                    origin=origin,
                    kept_as=keep(name),
                    note=note or "appended; ECS related.* is an array several fields can feed",
                )
            )
            continue

        if target and not target.startswith("related."):
            taken = claim(target, name)
            if taken is not None:
                mappings.append(
                    FieldMapping(
                        source_field=name,
                        target_field=taken,
                        es_type=_es_type(taken, profile),
                        origin=origin,
                        note=note,
                    )
                )
                continue
            note = None  # the conflict is recorded on its own; no need to repeat it

        custom = keep(name)
        mappings.append(
            FieldMapping(
                source_field=name,
                target_field=custom,
                es_type=_es_type(custom, profile),
                origin=MappingOrigin.CUSTOM,
                note=note,
            )
        )

    return mappings


def _ecs_target(
    profile: FieldProfile, gap: EcsGapReport
) -> tuple[str | None, MappingOrigin, str | None]:
    """The ECS field this profile resolves to, and how far it can be trusted."""
    name = profile.field_name

    if profile.is_ecs_compliant:
        if not _is_bare_field_set(name):
            return name, MappingOrigin.ECS, None
        # `host` and `service` pass the gap analysis' ECS check because their
        # first segment is an ECS field set. They are still field sets, not
        # fields: a value indexed directly under one collides with every
        # `host.*` the same index will hold.
        resolved = ecs_gap.NAME_TO_ECS.get(name.lower())
        if resolved and resolved != name:
            return resolved, MappingOrigin.HEURISTIC, (
                f"ECS has no field called '{name}' - it is a field set - so the value is "
                f"written to '{resolved}'"
            )
        return None, MappingOrigin.CUSTOM, (
            f"'{name}' is an ECS field set rather than an ECS field, so a value cannot be "
            "indexed under that name"
        )

    target = profile.suggested_ecs_field
    if not target:
        return None, MappingOrigin.CUSTOM, None
    origin = MappingOrigin.INTEGRATION if name in gap.mapped_fields else MappingOrigin.HEURISTIC
    return target, origin, None


# ------------------------------------------------------------- the processors


def _processors(
    fingerprint: LogFingerprint,
    mappings: Sequence[FieldMapping],
    source: TimestampSource | None,
    dataset: str,
    module: str,
    review: list[str],
    *,
    named: bool,
) -> list[dict[str, Any]]:
    """Render the plan as an ordered processor list."""
    processors: list[dict[str, Any]] = [
        {
            "script": {
                "description": "Drop blank values so typed ECS fields never see an empty string",
                "lang": "painless",
                "params": {
                    "fields": [mapping.source_field for mapping in mappings],
                    "blanks": sorted(NULL_PLACEHOLDERS),
                },
                "source": _DROP_BLANK_SOURCE,
            }
        },
        {"set": {"field": "ecs.version", "value": ECS_VERSION, "override": False}},
    ]

    if named:
        processors.append({"set": {"field": "event.module", "value": module, "override": False}})
        processors.append({"set": {"field": "event.dataset", "value": dataset, "override": False}})

    processors.extend(_timestamp_processors(fingerprint, source, review))

    for mapping in mappings:
        processors.extend(_field_processors(mapping))

    for mapping in mappings:
        if mapping.origin is MappingOrigin.TIMESTAMP or mapping.es_type not in _CONVERTED_TYPES:
            continue
        processors.append(
            {
                "convert": {
                    "field": mapping.target_field,
                    "type": mapping.es_type,
                    "ignore_missing": True,
                }
            }
        )

    return processors


def _field_processors(mapping: FieldMapping) -> list[dict[str, Any]]:
    """The one or two processors that move a single field into place."""
    processors: list[dict[str, Any]] = []

    if mapping.origin is MappingOrigin.TIMESTAMP:
        pass  # the date processor already read it; only the preserving rename is left
    elif mapping.target_field.startswith("related."):
        processors.append(
            {
                "append": {
                    "field": mapping.target_field,
                    "value": f"{{{{{{{mapping.source_field}}}}}}}",
                    "allow_duplicates": False,
                    "if": f"ctx['{mapping.source_field}'] != null",
                }
            }
        )
    elif mapping.renamed:
        processors.append(
            {
                "rename": {
                    "field": mapping.source_field,
                    "target_field": mapping.target_field,
                    "ignore_missing": True,
                }
            }
        )

    if mapping.kept_as:
        processors.append(
            {
                "rename": {
                    "field": mapping.source_field,
                    "target_field": mapping.kept_as,
                    "ignore_missing": True,
                }
            }
        )
    return processors


def _timestamp_processors(
    fingerprint: LogFingerprint,
    source: TimestampSource | None,
    review: list[str],
) -> list[dict[str, Any]]:
    """Write `@timestamp`, or say why it cannot be written yet.

    Nothing here falls back to ingest time. A data stream refusing a document
    with no `@timestamp` is a loud failure; an `@timestamp` holding the moment
    the log was shipped is a quiet one that survives all the way into a
    detection rule's time window.
    """
    if source is None:
        review.append(
            "No event-time column was recognised in this sample, so the pipeline writes no "
            "@timestamp. A data stream rejects documents without one - add a date processor for "
            "whichever field carries event time before deploying."
        )
        return []

    if not source.is_readable:
        ask = source.format_requirements[0] if source.format_requirements else ""
        review.append(
            f"Event time comes from {source.description}, but the sample does not settle how its "
            "date reads, so no date processor was written rather than one that could shift every "
            "event by months. " + (ask[0].upper() + ask[1:] + "." if ask else "")
        )
        return []

    if source.is_split:
        return _split_timestamp_processors(fingerprint, source, review)

    field = source.field_name or ""
    profile = fingerprint.profile_for(field)
    formats = _date_formats(
        profile.example if profile else None, profile.date_order if profile else None
    )
    if not formats:
        review.append(
            f"Event time comes from '{field}', but its format could not be expressed as a date "
            "pattern from the sample. Add the formats to a date processor before deploying."
        )
        return []

    return [_date_processor(field, formats, source, review)]


def _split_timestamp_processors(
    fingerprint: LogFingerprint,
    source: TimestampSource,
    review: list[str],
) -> list[dict[str, Any]]:
    """Join a date column and a time column, then parse the pair.

    W3C/IIS specifies event time this way and FortiGate writes it this way, so
    this is the normal case for two of the log sources the engine is built for,
    not an oddity to work around.
    """
    date_field, time_field = source.date_field or "", source.time_field or ""
    if not (_REFERENCEABLE_NAME.match(date_field) and _REFERENCEABLE_NAME.match(time_field)):
        review.append(
            f"Event time is split across '{date_field}' and '{time_field}', and at least one of "
            "those names cannot be referenced from an ingest template, so the join was left out. "
            "Write it by hand before deploying."
        )
        return []

    date_profile = fingerprint.profile_for(date_field)
    time_profile = fingerprint.profile_for(time_field)
    example = " ".join(
        part
        for part in (
            (date_profile.example if date_profile else None) or "",
            (time_profile.example if time_profile else None) or "",
        )
        if part
    )
    formats = _date_formats(example, date_profile.date_order if date_profile else None)
    if not formats:
        review.append(
            f"Event time is split across '{date_field}' and '{time_field}', but the joined format "
            "could not be expressed as a date pattern. Write the date processor by hand."
        )
        return []

    return [
        {
            "set": {
                "description": f"Join {date_field} and {time_field} into one event time",
                "field": TMP_EVENT_TIME,
                "value": f"{{{{{{{date_field}}}}}}} {{{{{{{time_field}}}}}}}",
                "if": f"ctx['{date_field}'] != null && ctx['{time_field}'] != null",
            }
        },
        _date_processor(TMP_EVENT_TIME, formats, source, review),
        {"remove": {"field": TMP_ROOT, "ignore_missing": True}},
    ]


def _date_processor(
    field: str,
    formats: list[str],
    source: TimestampSource,
    review: list[str],
) -> dict[str, Any]:
    options: dict[str, Any] = {
        "field": field,
        "target_field": "@timestamp",
        "formats": formats,
        # Stated rather than left to the cluster default, and it matches how the
        # engine itself read the column when it measured the sample's time span.
        "timezone": "UTC",
    }
    if source.declares_local_time:
        options["description"] = (
            f"{source.description} is labelled local time and carries no offset. Replace the "
            "timezone below with the site's IANA zone before deploying."
        )
        review.append(
            f"{source.description} declares local time and carries no UTC offset. The date "
            "processor assumes UTC; change its timezone to the site's own zone, or every event "
            "lands wrong by that offset."
        )
    return {"date": options}


# --------------------------------------------------------------- date formats


def _date_formats(example: str | None, date_order: str | None) -> list[str]:
    """Express one observed timestamp as Elasticsearch date patterns.

    Component widths are permissive on purpose: `H` parses both `8` and `08`,
    while `HH` refuses the first, and one sample row cannot prove that the whole
    column pads.
    """
    text = (example or "").strip()
    if not text:
        return []

    if text.isdigit():
        return {10: ["UNIX"], 13: ["UNIX_MS"]}.get(len(text), [])

    if _ISO_T_RE.match(text):
        return ["ISO8601"]

    slash = SLASH_DATE_RE.match(text)
    if slash is not None:
        if date_order == DATE_ORDER_DAY_FIRST:
            head = "d/M/yyyy"
        elif date_order == DATE_ORDER_MONTH_FIRST:
            head = "M/d/yyyy"
        else:
            return []
        if "-" in text.split(" ")[0]:
            head = head.replace("/", "-")
        clock = slash.group(4)
        if not clock:
            return [head]
        return [f"{head} {pattern}" for pattern in _clock_patterns(clock)]

    if _ISO_SPACE_RE.match(text):
        return [f"yyyy-MM-dd {pattern}" for pattern in _clock_patterns(text.split(" ", 1)[1])]

    if _DATE_ONLY_RE.match(text):
        return ["yyyy-MM-dd"]

    return []


def _clock_patterns(clock: str) -> list[str]:
    """Patterns for one observed clock, fractional seconds first when present."""
    head, _, fraction = clock.strip().partition(".")
    base = "H:mm:ss" if head.count(":") >= 2 else "H:mm"
    if not fraction:
        return [base]
    digits = len(re.sub(r"\D", "", fraction))
    # Both, because a column that writes `.030` on one row can write a whole
    # second with no fraction at all on the next.
    return [f"{base}.{'S' * digits}", base]


# ------------------------------------------------------------------- mappings


def _properties(mappings: Sequence[FieldMapping]) -> dict[str, Any]:
    """Nested `properties` for every field the pipeline can produce.

    Nested rather than dotted keys, because a dotted key in `properties` is only
    accepted by some versions and this template has to apply on whichever 8.x
    the client happens to run.
    """
    typed: dict[str, str] = {
        "@timestamp": "date",
        "ecs.version": "keyword",
        "tags": "keyword",
        "error.message": "match_only_text",
        "event.module": "keyword",
        "event.dataset": "keyword",
    }
    for mapping in mappings:
        typed.setdefault(mapping.target_field, mapping.es_type)
        if mapping.kept_as:
            # Preserved originals are raw text by definition: the value is kept
            # because something rewrote it, and a `16/07/2026` original under a
            # `date` mapping would fail to index the very row it documents.
            typed.setdefault(mapping.kept_as, "keyword")

    properties: dict[str, Any] = {}
    for field in sorted(typed):
        _insert(properties, field.split("."), typed[field])
    return properties


def _insert(properties: dict[str, Any], path: list[str], es_type: str) -> None:
    """Place one dotted field into a nested `properties` tree, leaves permitting."""
    head, rest = path[0], path[1:]
    node = properties.setdefault(head, {})
    if not rest:
        if "properties" not in node:
            node.update(_leaf(es_type))
        return
    if node and "properties" not in node:
        # A leaf already sits where an object has to go. Dropping the deeper
        # field is the safe half: the shallower one is the one a rule reads.
        return
    _insert(node.setdefault("properties", {}), rest, es_type)


def _leaf(es_type: str) -> dict[str, Any]:
    if es_type == "keyword":
        return {"type": "keyword", "ignore_above": 1024}
    return {"type": es_type}


def _es_type(target: str, profile: FieldProfile | None) -> str:
    if target in _EXACT_TYPES:
        return _EXACT_TYPES[target]
    for suffix, es_type in _SUFFIX_TYPES:
        if target.endswith(suffix):
            return es_type
    if profile is not None and not _has_leading_zero(profile):
        mapped = _DTYPE_TYPES.get(profile.dtype)
        if mapped:
            return mapped
    return "keyword"


def _has_leading_zero(profile: FieldProfile) -> bool:
    """Whether a column of digits is an identifier rather than a number.

    FortiGate's `logid` is `0000000013`. Indexed as a long it becomes 13, and the
    value a rule matches on no longer exists anywhere in the index.
    """
    values = [profile.example or ""] + [value for value, _ in profile.top_values]
    return any(_LEADING_ZERO_RE.match(value.strip()) for value in values if value)


# --------------------------------------------------------------------- naming


def _dataset_name(fingerprint: LogFingerprint, sample_name: str) -> tuple[str, str]:
    """`<module>` and `<module>.<dataset>`, from what classification could tell.

    The same two-part shape the official integrations use (`fortinet.firewall`),
    because that is what a `logs-<dataset>-<namespace>` data stream is named
    after and what `event.dataset` is expected to hold.
    """
    product = _slug(fingerprint.inferred_product)
    service = _slug(fingerprint.inferred_service)
    category = _slug(fingerprint.inferred_category)

    module = product or category or _slug(sample_name.rsplit(".", 1)[0]) or "custom"
    detail = service or (category if category != module else "") or "log"
    return module, f"{module}.{detail}"


def _namespace(module: str) -> str:
    """Where fields with no ECS home live.

    Never an ECS field set: putting `ClientRequestPath` under `host.*` because
    the product happened to be called `host` would collide with real ECS fields.
    """
    return f"{module}_custom" if module in ECS_ROOTS or module in ECS_SCALARS else module


def _custom_target(namespace: str, field_name: str) -> str:
    return f"{namespace}.{_snake(field_name) or 'field'}"


def _is_bare_field_set(name: str) -> bool:
    return "." not in name and name not in ECS_SCALARS and name in ECS_ROOTS


def _slug(text: str | None) -> str:
    return re.sub(r"_+", "_", re.sub(r"[^a-z0-9]+", "_", (text or "").lower())).strip("_")


def _snake(name: str) -> str:
    """`ClientRequestPath` -> `client_request_path`, `cs-method` -> `cs_method`."""
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    spaced = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", spaced)
    return _slug(spaced)


def _log_source(fingerprint: LogFingerprint) -> str:
    return " / ".join(
        [
            fingerprint.inferred_category or "?",
            fingerprint.inferred_product or "?",
            fingerprint.inferred_service or "?",
        ]
    )


# -------------------------------------------------------------------- review


def _review_notes(
    review: list[str],
    fingerprint: LogFingerprint,
    gap: EcsGapReport,
    mappings: Sequence[FieldMapping],
    conflicts: Sequence[str],
) -> None:
    """What a reviewer has to settle before this is applied to a cluster."""
    if gap.integration is not None:
        review.append(
            f"An official Elastic integration covers this shape ({gap.integration.name}). It is "
            "maintained by Elastic and stays current with ECS, so install it rather than this "
            "pipeline unless something rules it out."
        )

    heuristic = [mapping for mapping in mappings if mapping.origin is MappingOrigin.HEURISTIC]
    if heuristic:
        names = sorted(mapping.source_field for mapping in heuristic)
        review.append(
            f"{len(heuristic)} mapping(s) are the engine's own reading of the field name and its "
            f"values, not a mapping the vendor states ({', '.join(names[:6])}"
            + (", ..." if len(names) > 6 else "")
            + "). Confirm them against the log's documentation."
        )

    custom = [mapping for mapping in mappings if mapping.origin is MappingOrigin.CUSTOM]
    if custom:
        review.append(
            f"{len(custom)} field(s) have no ECS equivalent and are moved under the vendor "
            "namespace rather than left at the root, so a later ECS release cannot collide with "
            "them. A rule that reads one of these has to use its new name."
        )

    if not fingerprint.official_integration_available and any(m.renamed for m in mappings):
        review.append(
            "Runbook drafts for a sample with no official integration are written against the "
            "sample's own field names, because that is what the index holds until a pipeline like "
            "this one exists. Once it is deployed, re-read those queries against the names here."
        )

    review.extend(conflicts)
