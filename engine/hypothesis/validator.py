"""Validate a hypothesis against what the sample can actually support (BLUEPRINT 5.5).

The five steps are the standard threat-hunting validation sequence, applied to
"does the data support building a rule" rather than "did this attack happen",
because the engine works from a static sample and not from live telemetry:

1. **reassess_data_patterns** - are the fields the Evidence names present at all?
2. **confirm_baselines** - is there enough distribution and history to tell
   normal from anomalous? Only asked when the behavior needs a baseline.
3. **correlate_threat_intel** - is this behavior codified anywhere locally, in
   the Sigma corpus or the internal taxonomy?
4. **contextual_filtering** - are timestamp granularity, sample span, and
   correlation fields enough for the rule type the behavior implies?
5. **document** - every result above, pass or fail, is carried into the report
   rather than collapsed into a verdict. That step is engine/hypothesis/report.py.

A check that does not apply is recorded as NOT_APPLICABLE, never as a pass. A
baseline question asked of a behavior that needs no baseline has no answer, and
reporting one would overstate what was verified.
"""

from __future__ import annotations

from enum import Enum
from typing import Sequence

from pydantic import BaseModel, Field, computed_field

from engine.hypothesis.able import EvidenceRequirement, Hypothesis
from engine.ingestion.schemas import LogRecord
from engine.matching.sigma_matcher import SigmaRuleIndex
from engine.profiling.field_profiler import LogFingerprint

# A behavior judged against "normal" needs enough events and enough elapsed time
# for "normal" to mean something. These are deliberately blunt: the point is to
# refuse to claim a baseline exists in a 40-event sample, not to be precise.
MIN_BASELINE_EVENTS = 200
MIN_BASELINE_SPAN_SECONDS = 24 * 3600
# The shortest window a volume rule is usually written against.
MIN_THRESHOLD_SPAN_SECONDS = 300

_RULE_TYPES_NEEDING_HISTORY = {"new_terms", "machine_learning"}
_RULE_TYPES_NEEDING_CORRELATION = {"threshold", "eql", "esql"}


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


class ValidationCheck(BaseModel):
    """One validation step's result.

    ``status`` carries the three real outcomes; ``passed`` stays available as the
    plan's schema describes it, and is true for anything that is not a failure.
    """

    name: str
    status: CheckStatus
    detail: str
    # What the check found lacking, for the report's remediation section.
    missing: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def passed(self) -> bool:
        return self.status is not CheckStatus.FAIL


class EvidenceResolution(BaseModel):
    """Which sample field, if any, satisfies one evidence requirement."""

    label: str
    required: bool
    field_name: str | None = None
    matched_by: str | None = None  # "ecs field" | "entity type" | "field name"

    @property
    def satisfied(self) -> bool:
        return self.field_name is not None


class SampleContext(BaseModel):
    """Facts about the sample that several checks need."""

    record_count: int = 0
    timestamp_description: str | None = None
    # True when event time arrives as a date column plus a time column, which
    # the ingest pipeline has to combine before any rule can window events.
    timestamp_needs_combining: bool = False
    # False when the column is an event time the engine refuses to read, which is
    # a different finding from having no event time at all.
    timestamp_readable: bool = True
    timestamp_ingest_requirements: list[str] = Field(default_factory=list)
    time_span_seconds: float | None = None
    sub_minute_granularity: bool = False
    free_text_field: str | None = None


def build_context(fingerprint: LogFingerprint, records: Sequence[LogRecord] | None = None) -> SampleContext:
    """Derive timestamp coverage and span once, for reuse across checks."""
    source = fingerprint.timestamp_source()
    context = SampleContext(
        record_count=fingerprint.record_count,
        timestamp_description=source.description if source else None,
        timestamp_needs_combining=bool(source and source.is_split),
        timestamp_readable=source.is_readable if source else True,
        timestamp_ingest_requirements=source.ingest_requirements if source else [],
        free_text_field=_free_text_field(fingerprint),
    )

    if source is None or not records:
        return context

    moments = []
    for record in records:
        parsed = source.resolve(record.fields)
        if parsed is not None:
            moments.append(parsed)

    if len(moments) >= 2:
        context.time_span_seconds = (max(moments) - min(moments)).total_seconds()
    if moments:
        context.sub_minute_granularity = any(moment.second or moment.microsecond for moment in moments)

    return context


def validate(
    hypothesis: Hypothesis,
    fingerprint: LogFingerprint,
    *,
    context: SampleContext,
    sigma_index: SigmaRuleIndex | None = None,
    taxonomy_techniques: set[str] | None = None,
) -> list[ValidationCheck]:
    """Run the four checks in order and return their results."""
    resolutions = resolve_evidence(hypothesis.evidence_requirements, fingerprint)
    return [
        _reassess_data_patterns(resolutions, context),
        _confirm_baselines(hypothesis, fingerprint, context, resolutions),
        _correlate_threat_intel(hypothesis, fingerprint, sigma_index, taxonomy_techniques or set()),
        _contextual_filtering(hypothesis, fingerprint, context),
    ]


def resolve_evidence(
    requirements: Sequence[EvidenceRequirement],
    fingerprint: LogFingerprint,
) -> list[EvidenceResolution]:
    """Find the sample field satisfying each requirement, most reliable route first."""
    return [_resolve_one(requirement, fingerprint) for requirement in requirements]


def _resolve_one(requirement: EvidenceRequirement, fingerprint: LogFingerprint) -> EvidenceResolution:
    wanted_ecs = {name.lower() for name in requirement.ecs_fields}

    # An explicit ECS mapping is the strongest evidence the field is what we want.
    for profile in fingerprint.profiles:
        ecs_name = profile.field_name if profile.is_ecs_compliant else profile.suggested_ecs_field
        if ecs_name and ecs_name.lower() in wanted_ecs:
            return EvidenceResolution(
                label=requirement.label, required=requirement.required,
                field_name=profile.field_name, matched_by="ecs field",
            )

    # Then what the values themselves look like.
    if requirement.entity_types:
        for profile in fingerprint.profiles:
            if profile.entity_type in requirement.entity_types:
                return EvidenceResolution(
                    label=requirement.label, required=requirement.required,
                    field_name=profile.field_name, matched_by="entity type",
                )

    # Weakest: the name. Kept last because names lie more often than values do.
    for profile in fingerprint.profiles:
        lowered = profile.field_name.lower()
        if any(keyword in lowered for keyword in requirement.name_keywords):
            return EvidenceResolution(
                label=requirement.label, required=requirement.required,
                field_name=profile.field_name, matched_by="field name",
            )

    return EvidenceResolution(label=requirement.label, required=requirement.required)


# --------------------------------------------------------------------- checks


def _reassess_data_patterns(
    resolutions: Sequence[EvidenceResolution],
    context: SampleContext,
) -> ValidationCheck:
    missing = [r.label for r in resolutions if r.required and not r.satisfied]
    found = [f"{r.label} <- {r.field_name} (by {r.matched_by})" for r in resolutions if r.satisfied]

    if not missing:
        detail = "Every required field is present: " + "; ".join(found) if found else "No evidence required."
        return ValidationCheck(name="reassess_data_patterns", status=CheckStatus.PASS, detail=detail)

    detail = f"Missing required evidence: {', '.join(missing)}."
    if found:
        detail += " Present: " + "; ".join(found) + "."
    if context.free_text_field:
        detail += (
            f" The sample does carry a free-text field ('{context.free_text_field}') which may hold these "
            "values unparsed; extracting them at ingest would satisfy this check without new log data."
        )
    return ValidationCheck(
        name="reassess_data_patterns", status=CheckStatus.FAIL, detail=detail, missing=missing
    )


def _confirm_baselines(
    hypothesis: Hypothesis,
    fingerprint: LogFingerprint,
    context: SampleContext,
    resolutions: Sequence[EvidenceResolution],
) -> ValidationCheck:
    if not hypothesis.needs_baseline:
        return ValidationCheck(
            name="confirm_baselines",
            status=CheckStatus.NOT_APPLICABLE,
            detail=(
                f"This behavior is evaluated per event, not against a baseline "
                f"({hypothesis.implied_rule_type or 'single-event'} rule), so no baseline is required."
            ),
        )

    problems: list[str] = []
    if context.record_count < MIN_BASELINE_EVENTS:
        problems.append(
            f"only {context.record_count} events in the sample, below the {MIN_BASELINE_EVENTS} "
            "a baseline needs"
        )
    if context.time_span_seconds is None and not context.timestamp_readable:
        problems.append(
            f"the sample's time span could not be determined: the date order in "
            f"{context.timestamp_description} is unsettled, so no event can be placed on a timeline"
        )
    elif context.time_span_seconds is None:
        problems.append("the sample's time span could not be determined")
    elif context.time_span_seconds < MIN_BASELINE_SPAN_SECONDS:
        problems.append(
            f"the sample spans {_humanise(context.time_span_seconds)}, short of the "
            f"{_humanise(MIN_BASELINE_SPAN_SECONDS)} needed to know what is routine"
        )

    flat = [
        r.field_name for r in resolutions
        if r.satisfied and (profile := fingerprint.profile_for(r.field_name or "")) and profile.cardinality <= 1
    ]
    if flat:
        problems.append(f"single-valued in this sample, so they cannot discriminate: {', '.join(flat)}")

    if problems:
        return ValidationCheck(
            name="confirm_baselines",
            status=CheckStatus.FAIL,
            detail="A baseline cannot be established from this sample: " + "; ".join(problems) + ".",
            missing=["a longer sample: more events and a wider time range"],
        )

    return ValidationCheck(
        name="confirm_baselines",
        status=CheckStatus.PASS,
        detail=(
            f"{context.record_count} events over {_humanise(context.time_span_seconds or 0)} is enough "
            "to characterise normal behavior for this hypothesis."
        ),
    )


def _correlate_threat_intel(
    hypothesis: Hypothesis,
    fingerprint: LogFingerprint,
    sigma_index: SigmaRuleIndex | None,
    taxonomy_techniques: set[str],
) -> ValidationCheck:
    if not hypothesis.mitre_techniques:
        return ValidationCheck(
            name="correlate_threat_intel",
            status=CheckStatus.NOT_APPLICABLE,
            detail="This hypothesis carries no MITRE technique to correlate against.",
        )

    if sigma_index is None:
        return ValidationCheck(
            name="correlate_threat_intel",
            status=CheckStatus.NOT_APPLICABLE,
            detail="The Sigma corpus is not available locally, so no correlation could be attempted.",
        )

    wanted = {technique.upper() for technique in hypothesis.mitre_techniques}
    anywhere: list[str] = []
    same_source: list[str] = []
    for rule in sigma_index.rules:
        techniques = {technique.upper() for technique in rule.mitre_techniques}
        if not (techniques & wanted) and not any(
            technique.startswith(tuple(f"{w}." for w in wanted)) for technique in techniques
        ):
            continue
        anywhere.append(rule.title)
        if _same_logsource(rule, fingerprint):
            same_source.append(rule.title)

    in_taxonomy = sorted(wanted & {technique.upper() for technique in taxonomy_techniques})

    if not anywhere and not in_taxonomy:
        return ValidationCheck(
            name="correlate_threat_intel",
            status=CheckStatus.FAIL,
            detail=(
                f"No local knowledge covers {', '.join(sorted(wanted))}: no Sigma rule carries the "
                "technique and the internal taxonomy has no entry for it. Detection logic would have "
                "to be written from scratch."
            ),
            missing=[f"an internal taxonomy entry for {', '.join(sorted(wanted))}"],
        )

    detail = (
        f"{', '.join(sorted(wanted))} is codified locally: {len(anywhere)} Sigma rule(s)"
        + (f" and {len(in_taxonomy)} internal taxonomy entry(ies)" if in_taxonomy else "")
        + "."
    )
    if same_source:
        detail += f" {len(same_source)} of them target this log source, e.g. '{same_source[0]}'."
    else:
        detail += (
            " None of them target this log source, which is why matching found nothing: the behavior is "
            "well understood, just not from this telemetry."
        )
        if anywhere:
            detail += f" Closest existing rule: '{sorted(anywhere)[0]}'."
    return ValidationCheck(name="correlate_threat_intel", status=CheckStatus.PASS, detail=detail)


def _contextual_filtering(
    hypothesis: Hypothesis,
    fingerprint: LogFingerprint,
    context: SampleContext,
) -> ValidationCheck:
    rule_type = hypothesis.implied_rule_type
    if rule_type is None:
        return ValidationCheck(
            name="contextual_filtering",
            status=CheckStatus.NOT_APPLICABLE,
            detail="No rule type is implied until the log source is identified.",
        )

    problems: list[str] = []
    missing: list[str] = []

    if context.timestamp_description is None:
        problems.append("no timestamp field was found, so no rule can be time-scoped or investigated")
        # Same wording as the evidence requirement's label, so the report's
        # onboarding list asks for it once rather than twice in two phrasings.
        missing.append("event timestamp")
    elif not context.timestamp_readable:
        # Not a granularity problem: 16/07/2026 20:26:12.030 has sub-second
        # precision. Nothing parsed, so claiming coarse timestamps would be wrong.
        problems.append(
            f"{context.timestamp_description} carries an event time the engine will not read: its "
            "day/month order is unsettled, so events cannot be ordered or windowed"
        )
        missing.append("a confirmed timestamp format")
    elif not context.sub_minute_granularity and rule_type in _RULE_TYPES_NEEDING_CORRELATION:
        problems.append(
            f"timestamps in {context.timestamp_description} have no sub-minute component, too coarse "
            f"to order or window events for a {rule_type} rule"
        )
        missing.append("timestamps with at least second granularity")

    if rule_type in _RULE_TYPES_NEEDING_CORRELATION:
        resolutions = resolve_evidence(hypothesis.correlation_requirements, fingerprint)
        absent = [r.label for r in resolutions if not r.satisfied]
        if absent:
            problems.append(f"no field to group events by: {', '.join(absent)}")
            missing.extend(absent)
        if context.time_span_seconds is not None and context.time_span_seconds < MIN_THRESHOLD_SPAN_SECONDS:
            problems.append(
                f"the sample spans {_humanise(context.time_span_seconds)}, less than the "
                f"{_humanise(MIN_THRESHOLD_SPAN_SECONDS)} window a {rule_type} rule is normally written "
                "against, so the threshold cannot be calibrated from it"
            )
            missing.append("a sample covering at least one full detection window")

    if rule_type in _RULE_TYPES_NEEDING_HISTORY and context.record_count < MIN_BASELINE_EVENTS:
        problems.append(f"a {rule_type} rule needs historical volume this sample does not have")
        missing.append("historical data volume")

    if problems:
        return ValidationCheck(
            name="contextual_filtering",
            status=CheckStatus.FAIL,
            detail=f"Not enough context for the implied {rule_type} rule: " + "; ".join(problems) + ".",
            missing=missing,
        )

    detail = (
        f"Timestamp granularity, sample span, and correlation fields are sufficient for a "
        f"{rule_type} rule."
    )
    if context.timestamp_needs_combining:
        detail += (
            f" Event time arrives split across {context.timestamp_description}; the ingest pipeline "
            "must combine them into @timestamp before the rule can window events."
        )
    return ValidationCheck(name="contextual_filtering", status=CheckStatus.PASS, detail=detail)


# -------------------------------------------------------------------- helpers


def _same_logsource(rule, fingerprint: LogFingerprint) -> bool:
    for rule_value, sample_value in (
        (rule.category, fingerprint.inferred_category),
        (rule.product, fingerprint.inferred_product),
        (rule.service, fingerprint.inferred_service),
    ):
        if rule_value is None:
            continue
        if sample_value is None or rule_value.lower() != sample_value.lower():
            return False
    return True


def _free_text_field(fingerprint: LogFingerprint) -> str | None:
    """A high-cardinality string field likely to hold unparsed detail."""
    for profile in fingerprint.profiles:
        if profile.dtype != "string" or profile.example is None:
            continue
        if profile.field_name.lower() in {"message", "msg", "raw", "log", "description", "details"}:
            return profile.field_name
        if len(profile.example) > 80 and profile.cardinality > 1:
            return profile.field_name
    return None


def _humanise(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f} seconds"
    if seconds < 5400:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"
