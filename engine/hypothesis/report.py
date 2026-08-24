"""Turn validated hypotheses into a rejection report (docs/BLUEPRINT.md 5.5).

This is the fifth validation step, "document and report": every check, passed or
failed, is written down. The output is deliberately not a dead end. It gives the
analyst a starting point for manual work, and it gives the implementation project
a concrete list of fields to ask the client for, which is the form the blueprint
wants: onboarding requirements, not a note to tune something later.

Two verdicts are possible, because "rejected" is not always the truth:

* ``rejected`` - a check failed. The data cannot support this hypothesis yet.
* ``feasible_no_rule`` - every check passed. The data *would* support a rule;
  what is missing is the rule itself. The action is to author one and encode it
  back into the internal taxonomy, per docs/BLUEPRINT.md 5.3b.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Sequence

from pydantic import BaseModel, Field

from engine.hypothesis.able import Hypothesis, build_hypotheses
from engine.hypothesis.validator import (
    CheckStatus,
    EvidenceResolution,
    SampleContext,
    ValidationCheck,
    build_context,
    resolve_evidence,
    validate,
)
from engine.ingestion.schemas import LogRecord
from engine.matching.sigma_matcher import SigmaRuleIndex
from engine.profiling.entity_recognition import EntityType
from engine.profiling.field_profiler import EventExample, LogFingerprint, build_examples

VERDICT_REJECTED = "rejected"
VERDICT_FEASIBLE_NO_RULE = "feasible_no_rule"

# Columns to lead the example-events table with when the sample carries no
# recognisable entity to lead with instead.
_FALLBACK_LEAD_FIELDS = 4

STEP_TITLES = {
    "reassess_data_patterns": "Reassess data & patterns",
    "confirm_baselines": "Confirm with baselines",
    "correlate_threat_intel": "Correlate with local threat intel",
    "contextual_filtering": "Contextual filtering",
}
_STATUS_LABELS = {
    CheckStatus.PASS: "pass",
    CheckStatus.FAIL: "FAIL",
    CheckStatus.NOT_APPLICABLE: "n/a",
}


class HypothesisReport(BaseModel):
    """One hypothesis, its checks, and what to do about it."""

    hypothesis: Hypothesis
    checks: list[ValidationCheck] = Field(default_factory=list)
    verdict: str = VERDICT_REJECTED
    remediation: str | None = None
    # Field by field: what the hypothesis asked for and what the sample answered
    # with. "Rejected" is a verdict; this is the reason, at the level someone can
    # act on when they go back to the client.
    evidence: list[EvidenceResolution] = Field(default_factory=list)

    @property
    def failed_checks(self) -> list[ValidationCheck]:
        return [check for check in self.checks if check.status is CheckStatus.FAIL]

    @property
    def missing_evidence(self) -> list[EvidenceResolution]:
        """Required fields no column in the sample satisfies."""
        return [item for item in self.evidence if item.required and not item.satisfied]

    @property
    def present_evidence(self) -> list[EvidenceResolution]:
        return [item for item in self.evidence if item.satisfied]

    @property
    def requirements(self) -> list[str]:
        """This hypothesis's own gaps, deduplicated, in first-seen order."""
        seen: dict[str, None] = {}
        for check in self.failed_checks:
            for item in check.missing:
                seen.setdefault(item, None)
        return list(seen)

    @property
    def rejection_reason(self) -> str | None:
        """Why this was rejected, in terms that can be taken to the client.

        "Rejected" is the verdict; this is the actionable half. A missing field
        is named as a field, because a field is what gets requested. When no
        field is missing, the gap is about how much the sample covers - a
        different ask, and one that should not be dressed up as a field.
        """
        if self.verdict != VERDICT_REJECTED:
            return None

        missing = self.missing_evidence
        if missing:
            return (
                "The sample carries no field for "
                + ", ".join(item.label for item in missing)
                + ". Everything else follows from that, or from how much data the sample covers."
            )

        gaps = self.requirements
        if gaps:
            return (
                "Every field this hypothesis needs is present. What the sample does not give "
                "is " + "; ".join(gaps) + "."
            )
        return self.failed_checks[0].detail if self.failed_checks else None


class RejectionReport(BaseModel):
    """The whole document: every hypothesis asked of one sample."""

    sample_path: str
    generated_at: str
    fingerprint: LogFingerprint
    context: SampleContext
    reports: list[HypothesisReport] = Field(default_factory=list)
    # Held once and rendered into every card and every single-hypothesis export:
    # the events are a property of the sample, not of one hypothesis.
    examples: list[EventExample] = Field(default_factory=list)

    @property
    def ingest_requirements(self) -> list[str]:
        """Asks about how the data arrives rather than about missing fields.

        The data is there; the ingest design has to join it up, settle how it is
        written, or anchor it to an offset. Still an ask, and it applies to every
        hypothesis drawn from this sample, so it belongs on both the whole report
        and each single-hypothesis export.
        """
        return list(self.context.timestamp_ingest_requirements)

    @property
    def onboarding_requirements(self) -> list[str]:
        """Every distinct gap, in first-seen order: the ask for the client."""
        seen: dict[str, None] = {item: None for item in self.ingest_requirements}
        for report in self.reports:
            for item in report.requirements:
                seen.setdefault(item, None)
        return list(seen)

    @property
    def rejected(self) -> list[HypothesisReport]:
        return [report for report in self.reports if report.verdict == VERDICT_REJECTED]

    @property
    def feasible(self) -> list[HypothesisReport]:
        return [report for report in self.reports if report.verdict == VERDICT_FEASIBLE_NO_RULE]


def build_report(
    sample_path: str,
    fingerprint: LogFingerprint,
    *,
    records: Sequence[LogRecord] | None = None,
    sigma_index: SigmaRuleIndex | None = None,
    taxonomy_techniques: set[str] | None = None,
) -> RejectionReport:
    """Ask every hypothesis the data category suggests, and validate each one."""
    context = build_context(fingerprint, records)
    reports: list[HypothesisReport] = []

    for hypothesis in build_hypotheses(fingerprint):
        checks = validate(
            hypothesis,
            fingerprint,
            context=context,
            sigma_index=sigma_index,
            taxonomy_techniques=taxonomy_techniques,
        )
        failed = [check for check in checks if check.status is CheckStatus.FAIL]
        verdict = VERDICT_REJECTED if failed else VERDICT_FEASIBLE_NO_RULE
        reports.append(
            HypothesisReport(
                hypothesis=hypothesis,
                checks=checks,
                verdict=verdict,
                remediation=_remediation(hypothesis, failed),
                # Recomputed rather than threaded out of validate(), which
                # resolves the same requirements for its own checks. Resolution
                # is a pure lookup over the fingerprint, so the two agree.
                evidence=resolve_evidence(hypothesis.evidence_requirements, fingerprint),
            )
        )

    source = fingerprint.timestamp_source()
    return RejectionReport(
        sample_path=sample_path,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        fingerprint=fingerprint,
        context=context,
        reports=reports,
        examples=build_examples(
            records or [],
            source=source,
            # No rule matched, so nothing singles out a column. The fields that
            # carry identity are what an analyst reads an unfamiliar log by.
            key_fields=_identifying_fields(fingerprint),
        ),
    )


def _identifying_fields(fingerprint: LogFingerprint) -> list[str]:
    """The columns an analyst orients by when reading an unfamiliar sample."""
    wanted = {
        EntityType.IP,
        EntityType.USER,
        EntityType.DOMAIN,
        EntityType.URL,
        EntityType.PROCESS_NAME,
        EntityType.FILE_PATH,
    }
    identifying = [
        profile.field_name for profile in fingerprint.profiles if profile.entity_type in wanted
    ]
    if identifying:
        return identifying

    # A minimal appliance log may carry no recognisable entity at all. Leading
    # with the first few columns still beats a table of nothing but line numbers.
    return [
        profile.field_name
        for profile in fingerprint.profiles
        if profile.dtype not in ("timestamp", "date", "time", "empty")
    ][:_FALLBACK_LEAD_FIELDS]


def _remediation(hypothesis: Hypothesis, failed: Sequence[ValidationCheck]) -> str | None:
    if not failed:
        return (
            "Nothing is missing from the data. What is missing is the rule: no existing Sigma rule or "
            "taxonomy entry targets this behavior on this log source. Author one, validate it against a "
            "larger sample, and encode it back into the internal taxonomy so the next project inherits it."
        )

    gaps: list[str] = []
    for check in failed:
        for item in check.missing:
            if item not in gaps:
                gaps.append(item)

    if not gaps:
        return "See the failed checks above; no single field would resolve them."

    lead = f"To make '{hypothesis.behavior}' testable on this source, the implementation needs: "
    return lead + "; ".join(gaps) + "."


def render_markdown(report: RejectionReport) -> str:
    """Render the report as review-ready markdown."""
    fingerprint = report.fingerprint
    triple = " / ".join(
        part or "?" for part in
        (fingerprint.inferred_category, fingerprint.inferred_product, fingerprint.inferred_service)
    )

    lines: list[str] = [
        "# Detection feasibility: rejection report",
        "",
        f"**Sample:** `{report.sample_path}`  ",
        f"**Generated:** {report.generated_at}  ",
        f"**Log source:** {triple} - "
        f"{fingerprint.data_category.value if fingerprint.data_category else 'uncategorised'}  ",
        f"**Sample size:** {report.context.record_count} events"
        + (f", spanning {_span(report.context)}" if report.context.time_span_seconds else "")
        + "  ",
        f"**Event time:** {_event_time_line(report.context)}  ",
        f"**Outcome:** {len(report.reports)} hypothesis(es) evaluated - "
        f"{len(report.rejected)} rejected, {len(report.feasible)} feasible without an existing rule",
        "",
        "> **No automatic match is not the same as not detectable.** This report says what this "
        "sample can and cannot support today. It is a triage aid, not a conclusion, and it ends at "
        "analyst review.",
        "",
    ]

    if fingerprint.data_category is not None and fingerprint.classification_confidence < 0.5:
        lines.extend([
            f"> **The data category itself is a guess** (confidence "
            f"{fingerprint.classification_confidence}). It was inferred from field names alone, with no "
            f"log source signature matching. The hypotheses below follow from that guess, so confirm the "
            f"source before acting on them.",
            "",
        ])

    lines.extend([
        "## Why matching returned nothing",
        "",
        _why_no_match(fingerprint),
        "",
    ])

    for position, hypothesis_report in enumerate(report.reports, start=1):
        lines.extend(
            _render_hypothesis(position, hypothesis_report, report.examples, report.context)
        )

    requirements = report.onboarding_requirements
    lines.extend(["## Onboarding requirements", ""])
    if requirements:
        lines.append(
            "Collected from every failed check above. These are asks for the client or the ingest "
            "design, not tuning notes for later:"
        )
        lines.append("")
        lines.extend(f"{index}. {item}" for index, item in enumerate(requirements, start=1))
    else:
        lines.append("None. Every hypothesis the data category suggests is supportable by this sample.")
    lines.append("")

    lines.extend([
        "## Next step",
        "",
        "Analyst review. Nothing here is deployed, and no rule is created from this document. "
        "Confirm or discard each hypothesis, then either raise the onboarding requirements with the "
        "client or author the missing detection logic and add it to the internal taxonomy.",
        "",
    ])

    return "\n".join(lines)


def render_hypothesis_markdown(report: RejectionReport, index: int) -> str:
    """Render one hypothesis as a document that stands on its own.

    The whole-report download is the right thing for reviewing a sample. This is
    the right thing for handing a client a single onboarding ask: sending five
    hypotheses and asking them to find the relevant one is a worse deliverable,
    and editing the others out by hand before sending is worse still.

    It repeats the sample, the log source and the framing that the combined
    report states once, because this file has to make sense on its own when it
    arrives detached from everything around it.
    """
    item = report.reports[index]
    hypothesis = item.hypothesis
    fingerprint = report.fingerprint
    triple = " / ".join(
        part or "?" for part in
        (fingerprint.inferred_category, fingerprint.inferred_product, fingerprint.inferred_service)
    )
    category = fingerprint.data_category.value if fingerprint.data_category else "uncategorised"

    lines: list[str] = [
        f"# Detection feasibility: {hypothesis.behavior}",
        "",
        f"**Verdict: {_verdict_text(item)}**",
        "",
        f"**Sample:** `{report.sample_path}`  ",
        f"**Generated:** {report.generated_at}  ",
        f"**Log source:** {triple} - {category}  ",
        f"**Sample size:** {report.context.record_count} events"
        + (f", spanning {_span(report.context)}" if report.context.time_span_seconds else "")
        + "  ",
        f"**Event time:** {_event_time_line(report.context)}",
        "",
        "> **No automatic match is not the same as not detectable.** This is one "
        "hypothesis assessed against one log sample. It says what that sample can and "
        "cannot support today, and it ends at analyst review.",
        "",
        *_able_table(hypothesis),
        *_coverage_line(hypothesis),
        *_rejection_reason(item),
        *_evidence_table(item, level="##"),
        "## Validation",
        "",
        *_checks_table(item.checks),
    ]

    if item.remediation:
        lines.extend([f"**Remediation.** {item.remediation}", ""])

    lines.extend(_events_table(report.examples, report.context, level="##"))

    requirements = list(dict.fromkeys(report.ingest_requirements + item.requirements))
    lines.extend(["## What this needs", ""])
    if requirements:
        lines.extend(f"{position}. {text}" for position, text in enumerate(requirements, start=1))
    else:
        lines.append(
            "Nothing from the client. The data supports this hypothesis; what is missing "
            "is a rule for it. Author one and add it to the internal taxonomy."
        )
    lines.extend([
        "",
        "## Next step",
        "",
        "Analyst review. Nothing here is deployed and no rule is created from this "
        "document. Confirm or discard the hypothesis, then either raise the requirements "
        "above with the client or author the missing detection logic.",
        "",
    ])

    return "\n".join(lines)


def hypothesis_filename(report: RejectionReport, index: int) -> str:
    """Name the file after the behaviour, so a folder of them can be read."""
    slug = re.sub(r"[^a-z0-9]+", "-", report.reports[index].hypothesis.behavior.lower()).strip("-")
    return f"rejection-{slug[:60] or index + 1}.md"


def _verdict_text(report: HypothesisReport) -> str:
    return "REJECTED" if report.verdict == VERDICT_REJECTED else "FEASIBLE - no existing rule covers it"


def _able_table(hypothesis: Hypothesis) -> list[str]:
    return [
        "| ABLE | |",
        "|---|---|",
        f"| Actor | {hypothesis.actor} |",
        f"| Behavior | {hypothesis.behavior} |",
        f"| Location | {hypothesis.location} |",
        f"| Evidence | {hypothesis.evidence} |",
        "",
    ]


def _coverage_line(hypothesis: Hypothesis) -> list[str]:
    details = []
    if hypothesis.mitre_techniques:
        details.append(f"MITRE: {', '.join(hypothesis.mitre_techniques)}")
    if hypothesis.implied_rule_type:
        details.append(f"implied Elastic rule type: {hypothesis.implied_rule_type}")
    return [" · ".join(details), ""] if details else []


def _evidence_table(report: HypothesisReport, *, level: str = "###") -> list[str]:
    """Which field the hypothesis wanted, and what the sample answered with.

    The verdict says rejected; this says *what is missing*, by name, which is the
    only form the gap can be taken back to the client in.
    """
    if not report.evidence:
        return []

    lines = [
        f"{level} Evidence this hypothesis needs",
        "",
        "| Evidence | Sample field | Matched by | Status |",
        "|---|---|---|---|",
    ]
    for item in report.evidence:
        if item.satisfied:
            status, field, route = "present", f"`{item.field_name}`", item.matched_by or "-"
        else:
            status = "**MISSING**" if item.required else "absent (optional)"
            field, route = "-", "-"
        lines.append(f"| {item.label} | {field} | {route} | {status} |")
    lines.append("")
    return lines


def _rejection_reason(report: HypothesisReport) -> list[str]:
    reason = report.rejection_reason
    return [f"**Rejected.** {reason}", ""] if reason else []


def _events_table(
    examples: Sequence[EventExample], context: SampleContext, *, level: str = "###"
) -> list[str]:
    """Real events from the sample, so the gaps above are read against the data."""
    if not examples:
        return []

    columns = list(dict.fromkeys(name for example in examples for name, _ in example.key_fields))
    show_time = any(example.raw_timestamp for example in examples)
    header = ["Line"]
    if show_time:
        header.append(
            "Event time"
            + (f" ({context.timestamp_description})" if context.timestamp_description else "")
        )
    header.extend(f"`{name}`" for name in columns)

    lines = [
        f"{level} Example events from the sample",
        "",
        "| " + " | ".join(header) + " |",
        "|" + "---|" * len(header),
    ]
    for example in examples:
        values = dict(example.key_fields)
        row = [str(example.line)]
        if show_time:
            raw = example.raw_timestamp or "-"
            row.append(f"`{raw}`" + ("" if example.timestamp else " (unreadable)"))
        row.extend(_cell(values.get(name)) for name in columns)
        lines.append("| " + " | ".join(row) + " |")

    first = examples[0]
    if first.other_fields:
        lines.extend([
            "",
            f"Line {first.line} in full:",
            "",
            "| Field | Value |",
            "|---|---|",
        ])
        lines.extend(
            f"| `{name}` | {_cell(value)} |"
            for name, value in first.key_fields + first.other_fields
        )
        if first.omitted_fields:
            lines.append(f"| | *and {first.omitted_fields} more field(s)* |")
    lines.append("")
    return lines


def _cell(value: str | None) -> str:
    if value is None or value == "":
        return "-"
    return "`" + value.replace("|", "\\|").replace("`", "'") + "`"


def _checks_table(checks: Sequence[ValidationCheck]) -> list[str]:
    lines = ["| Validation step | Result | Detail |", "|---|---|---|"]
    for check in checks:
        title = STEP_TITLES.get(check.name, check.name)
        detail = check.detail.replace("|", "\\|")
        lines.append(f"| {title} | {_STATUS_LABELS[check.status]} | {detail} |")
    lines.append("")
    return lines


def _render_hypothesis(
    position: int,
    report: HypothesisReport,
    examples: Sequence[EventExample],
    context: SampleContext,
) -> list[str]:
    hypothesis = report.hypothesis
    lines = [
        f"## Hypothesis {position}: {hypothesis.behavior}",
        "",
        f"**Verdict: {_verdict_text(report)}**",
        "",
        *_able_table(hypothesis),
        *_coverage_line(hypothesis),
        *_rejection_reason(report),
        *_evidence_table(report),
        *_checks_table(report.checks),
    ]

    if report.remediation:
        lines.extend([f"**Remediation.** {report.remediation}", ""])

    lines.extend(_events_table(examples, context))
    return lines


def _why_no_match(fingerprint: LogFingerprint) -> str:
    if fingerprint.inferred_category is None and fingerprint.inferred_product is None:
        return (
            "The log source could not be identified from its field names, so no Sigma rule's logsource "
            "could be confirmed against it. Every rule in the corpus pins at least a category, and "
            "matching a rule to an unknown source would be a guess. Identifying the source is the first "
            "requirement below; once it is known, add a signature to "
            "`engine/profiling/data_classifier.py` so the next sample from it classifies automatically."
        )
    triple = " / ".join(
        part for part in
        (fingerprint.inferred_category, fingerprint.inferred_product, fingerprint.inferred_service) if part
    )
    return (
        f"The sample was identified as `{triple}`, but no rule in the local Sigma corpus both targets "
        "that logsource and depends only on fields this sample carries. That is a coverage gap in the "
        "public corpus, not a statement that the source is undetectable - which is what the internal "
        "taxonomy exists to close."
    )


def _event_time_line(context: SampleContext) -> str:
    """Name the column event time comes from, and say if it cannot be read."""
    if context.timestamp_description is None:
        return "no timestamp column was found in this sample"
    if not context.timestamp_readable:
        return f"`{context.timestamp_description}` - present, but not readable as written"
    if context.timestamp_needs_combining:
        return f"`{context.timestamp_description}`, split across two columns"
    return f"`{context.timestamp_description}`"


def humanise_span(seconds: float | None) -> str:
    """A sample's elapsed time in the largest unit that stays readable."""
    seconds = seconds or 0
    if seconds < 90:
        return f"{seconds:.0f} seconds"
    if seconds < 5400:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def _span(context: SampleContext) -> str:
    return humanise_span(context.time_span_seconds)
