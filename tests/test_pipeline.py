"""Orchestrator tests: both branches of the pipeline, end to end."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine import pipeline
from engine.storage.db import REPO_ROOT
from engine.storage.taxonomy_store import TaxonomyEntry

FIXTURES = Path(__file__).parent / "fixtures"
CLOUDFLARE = FIXTURES / "cloudflare_waf_firewall_events.csv"
APPLIANCE = FIXTURES / "minimal_appliance_syslog.csv"
SIGMA_CORPUS = REPO_ROOT / "data" / "sigma-corpus" / "rules"

# Pointing at a directory that does not exist makes the Sigma corpus unavailable,
# so these tests exercise the pipeline without depending on the clone.
NO_CORPUS = Path("does-not-exist")


def _seed_entry() -> TaxonomyEntry:
    return TaxonomyEntry(
        slug="cloudflare-waf-sqli",
        name="Cloudflare WAF - SQL injection attempt",
        logsource_category="webserver",
        logsource_product="cloudflare",
        logsource_service="firewall_events",
        data_category="application_logs",
        required_fields=["ClientIP", "ClientRequestQuery", "Action"],
        detection_logic={
            "waf": {"Source": ["waf"], "Action": ["block", "log"], "RuleID": ["100015"]},
            "condition": "waf",
        },
        mitre_techniques=["T1190"],
        suggested_rule_type="custom_query",
        confidence=0.8,
    )


def test_match_branch_produces_candidates_types_predictions_and_runbooks():
    result = pipeline.process_log_sample(
        CLOUDFLARE, taxonomy=[_seed_entry()], sigma_corpus=NO_CORPUS, integrations_corpus=NO_CORPUS
    )

    assert result.matched is True
    assert result.sigma_corpus_available is False
    assert result.taxonomy_entries == 1

    candidate = result.candidates[0]
    assert candidate.rule_ref == "internal:cloudflare-waf-sqli"
    assert candidate.rule_ref in result.rule_types
    assert candidate.rule_ref in result.predictions
    assert result.predictions[candidate.rule_ref].backtest.matched_events == 5
    assert len(result.runbooks) == 1
    assert "# Runbook (draft)" in result.runbooks[0].markdown
    assert result.rejection is None


def test_no_match_branch_produces_a_rejection_report():
    result = pipeline.process_log_sample(
        APPLIANCE, sigma_corpus=NO_CORPUS, integrations_corpus=NO_CORPUS
    )

    assert result.matched is False
    assert result.candidates == []
    assert result.runbooks == []
    assert result.rejection is not None
    assert result.rejection.reports
    assert result.rejection.onboarding_requirements


def test_sample_summary_reports_what_parsing_found():
    result = pipeline.process_log_sample(
        CLOUDFLARE, sigma_corpus=NO_CORPUS, integrations_corpus=NO_CORPUS
    )

    assert result.sample.record_count == 37
    assert result.sample.field_count == 19
    assert result.sample.format == "csv"
    # Six rows carry URL-encoded query strings that ingestion decoded.
    assert result.sample.decoded_records == 6


def test_runbooks_can_be_skipped():
    result = pipeline.process_log_sample(
        CLOUDFLARE, taxonomy=[_seed_entry()], sigma_corpus=NO_CORPUS,
        integrations_corpus=NO_CORPUS, generate_runbooks=False,
    )

    assert result.candidates
    assert result.runbooks == []
    # Predictions are still produced; only the document generation is skipped.
    assert result.predictions


def test_top_bounds_the_expensive_steps():
    entries = [_seed_entry(), _seed_entry().model_copy(update={"slug": "second", "name": "Second"})]

    result = pipeline.process_log_sample(
        CLOUDFLARE, taxonomy=entries, top=1, sigma_corpus=NO_CORPUS, integrations_corpus=NO_CORPUS
    )

    assert len(result.candidates) == 2
    assert len(result.predictions) == 1
    assert len(result.runbooks) == 1
    # Rule type classification is cheap, so it covers every candidate.
    assert len(result.rule_types) == 2


def test_runbooks_are_written_when_a_directory_is_given(tmp_path):
    result = pipeline.process_log_sample(
        CLOUDFLARE, taxonomy=[_seed_entry()], sigma_corpus=NO_CORPUS,
        integrations_corpus=NO_CORPUS, runbook_dir=tmp_path,
    )

    written = list(tmp_path.glob("*.md"))
    assert len(written) == 1
    assert written[0].read_text(encoding="utf-8") == result.runbooks[0].markdown


def test_limit_truncates_ingestion():
    result = pipeline.process_log_sample(
        CLOUDFLARE, limit=10, sigma_corpus=NO_CORPUS, integrations_corpus=NO_CORPUS
    )

    assert result.sample.record_count == 10
    assert result.sample.truncated is True


def test_missing_sample_raises_parse_error():
    from engine.ingestion.parser import ParseError

    with pytest.raises(ParseError):
        pipeline.process_log_sample(FIXTURES / "nope.csv", sigma_corpus=NO_CORPUS)


@pytest.mark.skipif(not SIGMA_CORPUS.is_dir(), reason="Sigma corpus not cloned; run scripts/setup.ps1")
def test_end_to_end_with_the_real_corpus():
    result = pipeline.process_log_sample(CLOUDFLARE, taxonomy=[_seed_entry()], top=3)

    assert result.sigma_corpus_available is True
    assert len(result.candidates) > 5
    sources = {candidate.source.value for candidate in result.candidates}
    assert sources == {"sigma", "internal_taxonomy"}
    assert len(result.runbooks) == 3
    # A Sigma-derived runbook must carry a converted query, not the raw taxonomy field names.
    sigma_runbooks = [
        runbook for runbook in result.runbooks
        if runbook.match_candidate.rule_ref.startswith("sigma:")
    ]
    assert sigma_runbooks
    assert "```lucene" in sigma_runbooks[0].markdown
