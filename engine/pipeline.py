"""The orchestrator: one log sample in, a reviewable answer out (BLUEPRINT 4).

    ingestion -> profiling -> ECS gap -> matching (Sigma + internal taxonomy)
                     |
              MATCH -+- rule type -> backtest -> runbook
                     |
           NO MATCH -+- ABLE hypothesis -> validation -> rejection report

Everything the CLI does lives here, so the Phase 6 web layer wires up to one
function instead of reimplementing the flow. Both branches end at a human review
step; neither writes anything to Elastic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from pydantic import BaseModel, Field

from engine.classification import rule_type_classifier
from engine.classification.rule_type_classifier import RuleTypeDecision
from engine.hypothesis import report as rejection_report
from engine.hypothesis.report import RejectionReport
from engine.ingestion import parser as ingestion
from engine.matching import sigma_matcher, taxonomy_matcher
from engine.matching.candidate import MatchCandidate
from engine.prediction import backtest as prediction
from engine.prediction.backtest import PredictionResult
from engine.profiling import ecs_gap
from engine.profiling.data_classifier import classify
from engine.profiling.ecs_gap import EcsGapReport
from engine.profiling.field_profiler import LogFingerprint, build_fingerprint, profile_fields
from engine.runbook import generator as runbook_generator
from engine.runbook.generator import RunbookOutput
from engine.storage.taxonomy_store import TaxonomyEntry

DEFAULT_TOP = 10
DEFAULT_MIN_CONFIDENCE = 0.4


class SampleSummary(BaseModel):
    """What parsing the file revealed, without carrying every record along."""

    path: str
    format: str
    encoding: str
    delimiter: str | None = None
    record_count: int = 0
    field_count: int = 0
    truncated: bool = False
    decoded_records: int = 0
    problems: list[str] = Field(default_factory=list)


class PipelineResult(BaseModel):
    """Everything one run produced."""

    sample: SampleSummary
    fingerprint: LogFingerprint
    ecs_gap: EcsGapReport
    candidates: list[MatchCandidate] = Field(default_factory=list)
    rule_types: dict[str, RuleTypeDecision] = Field(default_factory=dict)
    predictions: dict[str, PredictionResult] = Field(default_factory=dict)
    runbooks: list[RunbookOutput] = Field(default_factory=list)
    rejection: RejectionReport | None = None

    sigma_corpus_rules: int = 0
    sigma_corpus_available: bool = False
    taxonomy_entries: int = 0

    @property
    def matched(self) -> bool:
        return bool(self.candidates)


def process_log_sample(
    path: str | Path,
    *,
    limit: int | None = None,
    top: int = DEFAULT_TOP,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    log_rate_per_day: float | None = None,
    taxonomy: Sequence[TaxonomyEntry] | None = None,
    sigma_corpus: str | Path | None = None,
    integrations_corpus: str | Path | None = None,
    rebuild_index: bool = False,
    runbook_dir: str | Path | None = None,
    generate_runbooks: bool = True,
) -> PipelineResult:
    """Run one sample end to end.

    ``top`` bounds the expensive steps: backtesting re-reads rule files and runs
    logic over every record, and runbook generation converts rules through
    pySigma. Matching itself still considers the whole corpus.
    """
    sample = ingestion.parse(path, limit=limit)

    profiles = profile_fields(sample.records, field_names=sample.field_names)
    classification = classify(sample.field_names)

    integration_index = ecs_gap.load_index(integrations_corpus, rebuild=rebuild_index)
    gap = ecs_gap.analyse(profiles, integration_index, product_hint=classification.inferred_product)

    fingerprint = build_fingerprint(
        profiles,
        classification,
        record_count=sample.record_count,
        integration_name=gap.integration.name if gap.integration else None,
    )

    entries = list(taxonomy or [])
    rule_index = sigma_matcher.load_rule_index(sigma_corpus, rebuild=rebuild_index)

    # BLUEPRINT 5.3: the two sources run in parallel, not as fallbacks.
    candidates: list[MatchCandidate] = []
    if rule_index is not None:
        candidates += sigma_matcher.match(fingerprint, rule_index, min_confidence=min_confidence)
    candidates += taxonomy_matcher.match(fingerprint, entries, min_confidence=min_confidence)
    candidates.sort(key=lambda candidate: (-candidate.confidence, candidate.title))

    entries_by_slug = {entry.slug: entry for entry in entries}
    rule_types = {
        candidate.rule_ref: rule_type_classifier.classify(
            candidate, fingerprint, taxonomy_entry=_entry_for(candidate, entries_by_slug)
        )
        for candidate in candidates
    }

    predictions: dict[str, PredictionResult] = {}
    runbooks: list[RunbookOutput] = []
    for candidate in candidates[:top]:
        entry = _entry_for(candidate, entries_by_slug)
        sigma_rule = (
            sigma_matcher.load_rule(rule_index, candidate.rule_path or "")
            if entry is None and rule_index is not None else None
        )
        forecast = prediction.predict(
            candidate, sample.records, fingerprint,
            sigma_rule=sigma_rule, taxonomy_entry=entry, log_rate_per_day=log_rate_per_day,
        )
        predictions[candidate.rule_ref] = forecast

        if generate_runbooks:
            runbooks.append(
                runbook_generator.generate(
                    candidate, fingerprint, rule_types[candidate.rule_ref], forecast,
                    sample_path=sample.path, sigma_rule=sigma_rule, taxonomy_entry=entry,
                    out_dir=runbook_dir,
                )
            )

    # BLUEPRINT 5.5: no match is the hypothesis module's path, not a dead end.
    rejection = None
    if not candidates:
        rejection = rejection_report.build_report(
            sample.path,
            fingerprint,
            records=sample.records,
            sigma_index=rule_index,
            taxonomy_techniques={
                technique for entry in entries for technique in entry.mitre_techniques
            },
        )

    return PipelineResult(
        sample=SampleSummary(
            path=sample.path,
            format=sample.format.value,
            encoding=sample.encoding,
            delimiter=sample.delimiter,
            record_count=sample.record_count,
            field_count=len(sample.field_names),
            truncated=sample.truncated,
            decoded_records=sum(1 for record in sample.records if record.raw_fields),
            problems=list(sample.problems),
        ),
        fingerprint=fingerprint,
        ecs_gap=gap,
        candidates=candidates,
        rule_types=rule_types,
        predictions=predictions,
        runbooks=runbooks,
        rejection=rejection,
        sigma_corpus_rules=len(rule_index.rules) if rule_index else 0,
        sigma_corpus_available=rule_index is not None,
        taxonomy_entries=len(entries),
    )


def _entry_for(
    candidate: MatchCandidate,
    entries_by_slug: dict[str, TaxonomyEntry],
) -> TaxonomyEntry | None:
    return entries_by_slug.get(candidate.rule_ref.removeprefix("internal:"))
