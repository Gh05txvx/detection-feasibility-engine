"""Generate a review-ready runbook for a match candidate (docs/BLUEPRINT.md 5.7).

The output is a document an analyst reviews and then hands to whoever builds the
rule, not a rule that gets deployed. Every runbook ends at the human review
checkpoint (5.8); nothing here writes to Kibana, and nothing here should be
read as a decision already made.

The draft query is produced by converting the matched Sigma rule with pySigma,
through a processing pipeline built from this sample's own field mapping. That
is the piece Phase 0 identified as missing: the shipped ECS pipelines cover
Windows and Zeek, not the webserver taxonomy, so a converted rule would
otherwise reference `cs-method`, a field name that exists in no Elastic index.

Which field names the query targets depends on what the implementation will do:

* an official integration was found -> ECS names, since installing it is the
  recommendation and it produces ECS;
* no integration -> the sample's own vendor field names, because that is what
  the index will hold unless someone writes a custom pipeline.

Either way the runbook states which, and prints the mapping it used.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, Field

from engine.classification.rule_type_classifier import ElasticRuleType, RuleTypeDecision
from engine.matching.candidate import MatchCandidate, MatchSource
from engine.prediction.backtest import PredictionResult
from engine.profiling.field_profiler import LogFingerprint
from engine.storage.taxonomy_store import TaxonomyEntry

# Rule types Elastic expresses as a base query plus rule configuration, rather
# than as a query language of their own.
_QUERY_PLUS_CONFIG = {
    ElasticRuleType.THRESHOLD,
    ElasticRuleType.NEW_TERMS,
    ElasticRuleType.INDICATOR_MATCH,
    ElasticRuleType.MACHINE_LEARNING,
}


class RunbookOutput(BaseModel):
    """One candidate's runbook, and where it was written."""

    rule_name: str
    objective: str
    mitre_mapping: list[str] = Field(default_factory=list)
    match_candidate: MatchCandidate
    rule_type: RuleTypeDecision
    prediction: PredictionResult
    markdown_path: str = ""
    markdown: str = ""


def generate(
    candidate: MatchCandidate,
    fingerprint: LogFingerprint,
    decision: RuleTypeDecision,
    forecast: PredictionResult,
    *,
    sample_path: str = "",
    sigma_rule: Any | None = None,
    taxonomy_entry: TaxonomyEntry | None = None,
    out_dir: str | Path | None = None,
) -> RunbookOutput:
    """Build the runbook for one candidate, optionally writing it to disk."""
    prefer_ecs = fingerprint.official_integration_available
    mapping = build_field_mapping(candidate, fingerprint, prefer_ecs=prefer_ecs)
    language, query, query_error = _draft_query(
        decision.elastic_type, mapping, sigma_rule=sigma_rule, taxonomy_entry=taxonomy_entry
    )

    markdown = _render(
        candidate, fingerprint, decision, forecast,
        sample_path=sample_path, mapping=mapping, prefer_ecs=prefer_ecs,
        language=language, query=query, query_error=query_error,
        taxonomy_entry=taxonomy_entry,
    )

    written = ""
    if out_dir is not None:
        directory = Path(out_dir)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{_slug(candidate)}.md"
        path.write_text(markdown, encoding="utf-8")
        written = str(path)

    return RunbookOutput(
        rule_name=candidate.title,
        objective=_objective(candidate, fingerprint),
        mitre_mapping=list(candidate.mitre_techniques),
        match_candidate=candidate,
        rule_type=decision,
        prediction=forecast,
        markdown_path=written,
        markdown=markdown,
    )


def build_field_mapping(
    candidate: MatchCandidate,
    fingerprint: LogFingerprint,
    *,
    prefer_ecs: bool,
) -> dict[str, str]:
    """Rule field name -> the field name the query should use."""
    mapping: dict[str, str] = {}
    for rule_field, sample_field in candidate.matched_fields.items():
        target = sample_field
        if prefer_ecs:
            profile = fingerprint.profile_for(sample_field)
            if profile is not None:
                ecs_name = (
                    profile.field_name if profile.is_ecs_compliant else profile.suggested_ecs_field
                )
                if ecs_name:
                    target = ecs_name
        mapping[rule_field] = target
    return mapping


# ------------------------------------------------------------- draft query


def _draft_query(
    elastic_type: ElasticRuleType,
    mapping: dict[str, str],
    *,
    sigma_rule: Any | None,
    taxonomy_entry: TaxonomyEntry | None,
) -> tuple[str, str, str | None]:
    """Return (language, query, error). Errors are reported, never hidden."""
    if taxonomy_entry is not None:
        return "kql", _taxonomy_query(taxonomy_entry, mapping), None
    if sigma_rule is None:
        return "", "", "no Sigma rule was available to convert"

    try:
        from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
        from sigma.processing.transformations import FieldMappingTransformation
    except ImportError as exc:  # pragma: no cover - pysigma is a hard dependency
        return "", "", f"pySigma is not available: {exc}"

    pipeline = ProcessingPipeline(
        name="sample_field_mapping",
        priority=10,
        items=[
            ProcessingItem(
                identifier="rule_fields_to_sample_fields",
                transformation=FieldMappingTransformation(dict(mapping)),
            )
        ],
    )

    backend_name, backend_class = _backend_for(elastic_type)
    if backend_class is None:
        return "", "", f"no converter is wired up for {elastic_type.value}"

    try:
        queries = backend_class(processing_pipeline=pipeline).convert_rule(sigma_rule)
    except Exception as exc:  # noqa: BLE001 - conversion failure is a finding, not a crash
        return backend_name, "", f"{type(exc).__name__}: {exc}"

    if not queries:
        return backend_name, "", "the backend produced no query"
    return backend_name, str(queries[0]), None


def _backend_for(elastic_type: ElasticRuleType) -> tuple[str, Any]:
    from sigma.backends.elasticsearch import EqlBackend, ESQLBackend, LuceneBackend

    if elastic_type is ElasticRuleType.EQL:
        return "eql", EqlBackend
    if elastic_type is ElasticRuleType.ESQL:
        return "esql", ESQLBackend
    # Threshold, New Terms, Indicator Match and ML rules all take a base query
    # plus configuration, so the base query is the useful thing to draft.
    return "lucene", LuceneBackend


def _taxonomy_query(entry: TaxonomyEntry, mapping: dict[str, str]) -> str:
    """Render a taxonomy entry's detection logic as draft KQL."""
    blocks: dict[str, str] = {}
    notes: list[str] = []

    for name, spec in entry.detection_logic.items():
        if name in {"condition", "aggregation"} or not isinstance(spec, dict):
            continue
        clauses: list[str] = []
        for raw_field, expected in spec.items():
            field_name, _, modifier_text = str(raw_field).partition("|")
            modifiers = [modifier for modifier in modifier_text.split("|") if modifier]
            target = mapping.get(field_name, field_name)
            values = expected if isinstance(expected, list) else [expected]

            if "re" in modifiers:
                notes.append(
                    f"// {target}: regular expression, which KQL cannot express. Use an ES|QL "
                    f"`rlike`, a runtime field, or a query_string regexp: {values[0]}"
                )
                continue
            clauses.append(_kql_clause(target, values, modifiers))

        if clauses:
            blocks[name] = " and ".join(clauses)

    condition = str(entry.detection_logic.get("condition") or " and ".join(blocks))
    condition = condition.split("|")[0].strip()

    query = condition
    for name, clause in blocks.items():
        query = re.sub(rf"\b{re.escape(name)}\b", f"({clause})", query)

    # Any block that produced no clause leaves its bare name behind.
    for name in entry.detection_logic:
        if name not in blocks and name not in {"condition", "aggregation"}:
            query = re.sub(rf"\b{re.escape(name)}\b", "true /* see note */", query)

    return "\n".join([*notes, query]) if notes else query


def _kql_clause(field: str, values: Sequence[Any], modifiers: Sequence[str]) -> str:
    rendered: list[str] = []
    for value in values:
        text = str(value)
        if "contains" in modifiers:
            rendered.append(f'*{text}*')
        elif "startswith" in modifiers:
            rendered.append(f'{text}*')
        elif "endswith" in modifiers:
            rendered.append(f'*{text}')
        else:
            rendered.append(text)

    quoted = " or ".join(f'"{item}"' for item in rendered)
    return f"{field}:({quoted})" if len(rendered) > 1 else f"{field}:{quoted}"


# ----------------------------------------------------------------- rendering


def _render(
    candidate: MatchCandidate,
    fingerprint: LogFingerprint,
    decision: RuleTypeDecision,
    forecast: PredictionResult,
    *,
    sample_path: str,
    mapping: dict[str, str],
    prefer_ecs: bool,
    language: str,
    query: str,
    query_error: str | None,
    taxonomy_entry: TaxonomyEntry | None,
) -> str:
    result = forecast.backtest
    triple = " / ".join(
        part or "?" for part in
        (fingerprint.inferred_category, fingerprint.inferred_product, fingerprint.inferred_service)
    )

    lines: list[str] = [
        f"# Runbook (draft): {candidate.title}",
        "",
        "> **Not deployed, not approved.** This is a review artefact produced from one log "
        "sample. An analyst confirms or discards it before any rule is created in Kibana.",
        "",
        f"**Generated:** {datetime.now(timezone.utc).isoformat(timespec='seconds')}  ",
        f"**Sample:** `{sample_path}`  ",
        f"**Source:** {candidate.rule_ref} ({candidate.source.value})  ",
        f"**Match confidence:** {candidate.confidence:.2f}  ",
        f"**Prediction tier:** {forecast.confidence_tier.value}",
        "",
        "## Objective",
        "",
        _objective(candidate, fingerprint),
        "",
        "## Coverage",
        "",
        "| | |",
        "|---|---|",
        f"| MITRE ATT&CK | {', '.join(candidate.mitre_techniques) or 'not mapped'} |",
        f"| Log source | {triple} |",
        f"| Data category | {fingerprint.data_category.value if fingerprint.data_category else 'unknown'} |",
        f"| Severity (from rule) | {candidate.level or 'not stated'} |",
        "",
        "## Data source and field dependencies",
        "",
    ]

    if fingerprint.official_integration_available:
        lines.append(
            f"Install the **{fingerprint.official_integration_name}** integration. The query below "
            "is written against the ECS field names that integration produces."
        )
    else:
        lines.append(
            "No official Elastic integration covers this source, so the query below is written "
            "against the sample's own field names. They will only be correct if the ingest "
            "pipeline preserves them."
        )
    lines.extend(["", "| Rule field | Query field | Sample column |", "|---|---|---|"])
    for rule_field, target in sorted(mapping.items()):
        sample_field = candidate.matched_fields.get(rule_field, "-")
        lines.append(f"| `{rule_field}` | `{target}` | `{sample_field}` |")
    lines.append("")

    if candidate.missing_fields:
        lines.extend([
            f"**Blocked:** the rule also needs {', '.join(f'`{f}`' for f in candidate.missing_fields)}, "
            "absent from this sample. Onboard these before building the rule.",
            "",
        ])

    lines.extend([
        "## Rule type",
        "",
        f"**{decision.elastic_type.value}**"
        + (f" — {decision.hunting_technique}" if decision.hunting_technique else ""),
        "",
        decision.reasoning,
        "",
    ])
    if decision.alternatives:
        lines.extend([
            "Also expressible as: " + ", ".join(f"`{t.value}`" for t in decision.alternatives)
            + ". The simplest sufficient type was chosen.",
            "",
        ])
    for caveat in decision.caveats:
        lines.append(f"- **Caveat:** {caveat}")
    if decision.caveats:
        lines.append("")

    lines.extend(["## Draft query", ""])
    if query_error:
        lines.extend([
            f"Conversion did not produce a query: {query_error}.",
            "",
            "Write the query by hand from the detection logic, using the field mapping above.",
            "",
        ])
    else:
        lines.extend([f"```{language}", query, "```", ""])
        if decision.elastic_type in _QUERY_PLUS_CONFIG:
            lines.extend([
                f"A **{decision.elastic_type.value}** rule takes this as its base query plus "
                "configuration:",
                "",
            ])
            lines.extend(_rule_configuration(decision.elastic_type, taxonomy_entry))
            lines.append("")

    lines.extend([
        "## Expected trigger",
        "",
    ])
    if result.evaluated:
        lines.append(
            f"Against the {result.total_events}-event sample the logic matched "
            f"**{result.matched_events}** event(s)"
            + (f", producing **{result.alerts}** alert(s) after aggregation" if result.alerts != result.matched_events else "")
            + f" ({result.match_rate:.1%} of events)."
        )
        if result.example_lines:
            lines.append(f"Matching sample lines: {', '.join(str(line) for line in result.example_lines)}.")
        if result.aggregation_note:
            lines.append("")
            lines.append(result.aggregation_note)
    else:
        lines.append(f"The logic could not be executed against the sample: {result.unsupported_reason}.")
    lines.append("")

    lines.extend([
        "## Predicted volume",
        "",
        f"- **Estimated alerts/day:** {forecast.estimated_alert_volume:,.1f} "
        f"(basis: {forecast.projection_basis})",
        f"- **Confidence tier:** {forecast.confidence_tier.value}",
        f"- **Flagged noisy:** {'yes' if forecast.noisy else 'no'}",
        "",
        forecast.notes,
        "",
        "## False positives to expect",
        "",
    ])
    false_positives = list(taxonomy_entry.false_positives) if taxonomy_entry else []
    if false_positives:
        lines.extend(f"- {item}" for item in false_positives)
    else:
        lines.append(
            "- Not recorded on the source rule. Establish these with the client before go-live; "
            "a rule with no known false positives has usually not been run yet."
        )
    lines.append("")

    if candidate.assumptions:
        lines.extend(["## Assumptions this rule depends on", ""])
        lines.extend(f"- {assumption}" for assumption in candidate.assumptions)
        lines.append("")

    lines.extend([
        "## Investigation steps",
        "",
        "For the analyst who receives the alert:",
        "",
    ])
    lines.extend(_investigation_steps(candidate, fingerprint, mapping))
    lines.extend([
        "",
        "## Review checklist",
        "",
        "- [ ] The log source and field mapping above match what was actually onboarded",
        "- [ ] The detection logic is right for this client, not just structurally valid",
        "- [ ] The predicted alert volume is acceptable to whoever triages it",
        "- [ ] False positives have been discussed with the client",
        "- [ ] Severity and risk score agreed",
        "- [ ] Reviewed by: ______________________  Date: ____________",
        "",
        "Only after this checklist is complete does anyone create the rule in Kibana.",
        "",
    ])

    return "\n".join(lines)


def _rule_configuration(elastic_type: ElasticRuleType, entry: TaxonomyEntry | None) -> list[str]:
    aggregation = (entry.detection_logic.get("aggregation") if entry else None) or {}

    if elastic_type is ElasticRuleType.THRESHOLD:
        group_by = ", ".join(f"`{field}`" for field in aggregation.get("group_by", [])) or "to be decided"
        return [
            f"- **Group by:** {group_by}",
            f"- **Threshold:** {aggregation.get('count_gte', 'to be decided')}",
            f"- **Window:** {aggregation.get('window', 'to be decided')} "
            "(set the rule's lookback to at least this)",
        ]
    if elastic_type is ElasticRuleType.NEW_TERMS:
        return [
            "- **New terms fields:** the entity that should be flagged when first seen",
            "- **History window:** long enough to establish what is already routine (30 days is typical)",
        ]
    if elastic_type is ElasticRuleType.INDICATOR_MATCH:
        return [
            "- **Indicator index:** the threat intel index to join against",
            "- **Indicator mapping:** which sample field matches which indicator field",
        ]
    if elastic_type is ElasticRuleType.MACHINE_LEARNING:
        return [
            "- **ML job:** must exist and be running before the rule can be enabled",
            "- **Licence:** confirm the platform tier includes ML",
        ]
    return []


def _investigation_steps(
    candidate: MatchCandidate,
    fingerprint: LogFingerprint,
    mapping: dict[str, str],
) -> list[str]:
    """A starting template, keyed to the fields this rule actually has."""
    steps = [
        "1. Confirm the alert is not a known-good source: check the triggering value against any "
        "agreed allowlist before anything else.",
    ]

    entity_fields = [
        profile.field_name for profile in fingerprint.profiles
        if profile.entity_type is not None
    ]
    if entity_fields:
        steps.append(
            f"2. Pivot on the entities in the event ({', '.join(f'`{f}`' for f in entity_fields[:4])}): "
            "what else did they do in the surrounding window?"
        )
    else:
        steps.append("2. Pivot on whatever identifies the actor in this event; no entity field was recognised automatically.")

    steps.extend([
        "3. Establish whether this is a one-off or part of a pattern: same source, repeated attempts, "
        "or a spread across many targets.",
        f"4. Check the raw event against the rule's own logic ({candidate.rule_ref}) to confirm it "
        "fired for the reason intended, not on an edge case.",
        "5. If benign, record why and feed it back as a tuning exclusion or a taxonomy note, so the "
        "next analyst does not repeat the work.",
        "6. If malicious, escalate per the client's IR process. Containment and eradication are "
        "outside this engine's scope.",
    ])
    return steps


def _objective(candidate: MatchCandidate, fingerprint: LogFingerprint) -> str:
    techniques = ", ".join(candidate.mitre_techniques)
    where = fingerprint.inferred_product or fingerprint.inferred_category or "this log source"
    if candidate.source is MatchSource.INTERNAL_TAXONOMY:
        origin = "an internally curated taxonomy entry"
    else:
        origin = "a public Sigma rule"
    return (
        f"Detect **{candidate.title}** in {where} logs, from {origin}"
        + (f", covering {techniques}" if techniques else "")
        + "."
    )


def _slug(candidate: MatchCandidate) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", candidate.title.lower()).strip("-")
    reference = re.sub(r"[^a-z0-9]+", "-", candidate.rule_ref.lower()).strip("-")
    return f"{base[:60]}--{reference[-12:]}" if base else reference
