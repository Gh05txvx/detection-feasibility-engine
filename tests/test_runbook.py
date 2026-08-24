"""Runbook generator tests: field targeting, draft queries, and required sections."""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.rule import SigmaRule

from engine.classification.rule_type_classifier import ElasticRuleType, RuleTypeDecision
from engine.matching.candidate import MatchCandidate, MatchSource
from engine.prediction.backtest import BacktestResult, ConfidenceTier, PredictionResult
from engine.profiling.field_profiler import FieldProfile, LogFingerprint
from engine.runbook.generator import build_field_mapping, generate
from engine.storage.taxonomy_store import TaxonomyEntry


def _fingerprint(*, integration: str | None = "cloudflare_logpush / firewall_event") -> LogFingerprint:
    return LogFingerprint(
        profiles=[
            FieldProfile(field_name="ClientRequestMethod", dtype="string", cardinality=2, null_rate=0.0,
                         suggested_ecs_field="http.request.method"),
            FieldProfile(field_name="ClientRequestQuery", dtype="string", cardinality=9, null_rate=0.3,
                         suggested_ecs_field="url.query"),
            FieldProfile(field_name="ClientIP", dtype="string", cardinality=8, null_rate=0.0,
                         suggested_ecs_field="source.ip"),
        ],
        inferred_category="webserver",
        inferred_product="cloudflare",
        inferred_service="firewall_events",
        official_integration_available=integration is not None,
        official_integration_name=integration,
        record_count=37,
    )


def _candidate(**overrides) -> MatchCandidate:
    defaults = dict(
        source=MatchSource.SIGMA,
        rule_ref="sigma:7cb02516-6d95-4ffc-8eee-162075e111ac",
        confidence=0.8,
        title="Test rule",
        mitre_techniques=["T1190"],
        matched_fields={"cs-method": "ClientRequestMethod", "cs-uri-query": "ClientRequestQuery"},
    )
    defaults.update(overrides)
    return MatchCandidate(**defaults)


def _decision(rule_type: ElasticRuleType = ElasticRuleType.CUSTOM_QUERY, **overrides) -> RuleTypeDecision:
    defaults = dict(elastic_type=rule_type, reasoning="because the test says so")
    defaults.update(overrides)
    return RuleTypeDecision(**defaults)


def _forecast(**overrides) -> PredictionResult:
    defaults = dict(
        estimated_alert_volume=12.0,
        confidence_tier=ConfidenceTier.MEDIUM,
        notes="12 of 100 events match.",
        backtest=BacktestResult(evaluated=True, total_events=100, matched_events=12, alerts=12,
                                match_rate=0.12, example_lines=[2, 5]),
        projection_basis="sample time span",
    )
    defaults.update(overrides)
    return PredictionResult(**defaults)


def _sigma_rule() -> SigmaRule:
    return SigmaRule.from_yaml(
        "title: Test rule\n"
        "id: 7cb02516-6d95-4ffc-8eee-162075e111ac\n"
        "status: test\n"
        "logsource:\n"
        "    category: webserver\n"
        "detection:\n"
        "    selection:\n"
        "        cs-method: 'GET'\n"
        "        cs-uri-query|contains: 'union select'\n"
        "    condition: selection\n"
    )


# ------------------------------------------------------------- field targeting


def test_query_targets_ecs_when_an_integration_is_available():
    mapping = build_field_mapping(_candidate(), _fingerprint(), prefer_ecs=True)

    assert mapping == {"cs-method": "http.request.method", "cs-uri-query": "url.query"}


def test_query_targets_vendor_names_when_no_integration_exists():
    mapping = build_field_mapping(_candidate(), _fingerprint(integration=None), prefer_ecs=False)

    assert mapping == {"cs-method": "ClientRequestMethod", "cs-uri-query": "ClientRequestQuery"}


# --------------------------------------------------------------- draft query


def test_sigma_rule_converts_with_the_sample_field_mapping():
    """The Phase 0 gap: converted rules must not reference cs-method."""
    runbook = generate(_candidate(), _fingerprint(), _decision(), _forecast(), sigma_rule=_sigma_rule())

    assert "```lucene" in runbook.markdown
    assert "http.request.method" in runbook.markdown
    assert "cs-method:" not in runbook.markdown.split("## Draft query")[1].split("```")[1]


def test_taxonomy_entry_renders_a_kql_draft():
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={
            "waf": {"Source": ["waf"], "Action": ["block", "log"]},
            "condition": "waf",
        },
    )
    candidate = _candidate(source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={})

    runbook = generate(candidate, _fingerprint(), _decision(), _forecast(), taxonomy_entry=entry)

    assert "```kql" in runbook.markdown
    assert 'Source:"waf"' in runbook.markdown
    assert 'Action:("block" or "log")' in runbook.markdown


def test_block_name_appearing_in_a_value_does_not_corrupt_the_query():
    """Substituting block by block re-scans text already inserted."""
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={
            "waf": {"Action": ["block"]},
            "block": {"Source": ["firewall"]},
            "condition": "waf or block",
        },
    )
    candidate = _candidate(source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={})

    markdown = generate(candidate, _fingerprint(), _decision(), _forecast(), taxonomy_entry=entry).markdown
    query = markdown.split("```kql")[1].split("```")[0].strip()

    assert query.count("Source:") == 1
    assert 'Action:"block"' in query
    assert "Action:(Source:" not in query


def test_quotes_inside_a_value_are_escaped():
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={"sel": {"Msg": ['he said "hi"']}, "condition": "sel"},
    )
    candidate = _candidate(source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={})

    markdown = generate(candidate, _fingerprint(), _decision(), _forecast(), taxonomy_entry=entry).markdown
    query = markdown.split("```kql")[1].split("```")[0].strip()

    assert query == r'(Msg:"he said \"hi\"")'


def test_contains_renders_as_an_unquoted_wildcard():
    """In KQL a `*` inside quotes is a literal asterisk, not a wildcard."""
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={"sel": {"Query|contains": ["union select"]}, "condition": "sel"},
    )
    candidate = _candidate(source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={})

    markdown = generate(candidate, _fingerprint(), _decision(), _forecast(), taxonomy_entry=entry).markdown
    query = markdown.split("```kql")[1].split("```")[0].strip()

    assert query == r"(Query:*union\ select*)"


def test_regex_logic_is_flagged_as_inexpressible_in_kql():
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={"payload": {"Query|re": r"union\s+select"}, "condition": "payload"},
    )
    candidate = _candidate(source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={})

    runbook = generate(candidate, _fingerprint(), _decision(), _forecast(), taxonomy_entry=entry)

    assert "KQL cannot express" in runbook.markdown
    assert "rlike" in runbook.markdown


def test_conversion_failure_is_reported_not_hidden():
    runbook = generate(_candidate(), _fingerprint(), _decision(), _forecast(), sigma_rule=None)

    assert "Conversion did not produce a query" in runbook.markdown
    assert "by hand" in runbook.markdown


def test_threshold_rule_includes_its_configuration():
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.7,
        detection_logic={
            "failed": {"status": ["401"]},
            "aggregation": {"group_by": ["ClientIP"], "count_gte": 20, "window": "5m"},
            "condition": "failed",
        },
    )
    candidate = _candidate(source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={})

    runbook = generate(candidate, _fingerprint(), _decision(ElasticRuleType.THRESHOLD), _forecast(),
                       taxonomy_entry=entry)

    assert "**Group by:** `ClientIP`" in runbook.markdown
    assert "**Threshold:** 20" in runbook.markdown
    assert "**Window:** 5m" in runbook.markdown


# ------------------------------------------------------- BLUEPRINT 5.7 sections


@pytest.mark.parametrize(
    "heading",
    ["## Objective", "## Coverage", "## Data source and field dependencies", "## Rule type",
     "## Draft query", "## Expected trigger", "## Predicted volume", "## False positives to expect",
     "## Investigation steps", "## Review checklist"],
)
def test_runbook_contains_every_required_section(heading):
    runbook = generate(_candidate(), _fingerprint(), _decision(), _forecast(), sigma_rule=_sigma_rule())

    assert heading in runbook.markdown


def test_runbook_states_it_is_not_deployed():
    """BLUEPRINT 5.8: every output ends at human review, never at a write to Elastic."""
    runbook = generate(_candidate(), _fingerprint(), _decision(), _forecast(), sigma_rule=_sigma_rule())

    assert "Not deployed, not approved" in runbook.markdown
    assert "before any rule is created in Kibana" in runbook.markdown


def test_missing_fields_block_the_runbook_loudly():
    candidate = _candidate(missing_fields=["cs-cookie"])

    runbook = generate(candidate, _fingerprint(), _decision(), _forecast(), sigma_rule=_sigma_rule())

    assert "**Blocked:**" in runbook.markdown
    assert "cs-cookie" in runbook.markdown


def test_taxonomy_false_positives_and_assumptions_are_carried_in():
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={"selection": {"Action": ["block"]}, "condition": "selection"},
        false_positives=["Scheduled pentest windows"],
    )
    candidate = _candidate(
        source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={},
        assumptions=["the query string is URL-decoded at ingest"],
    )

    runbook = generate(candidate, _fingerprint(), _decision(), _forecast(), taxonomy_entry=entry)

    assert "Scheduled pentest windows" in runbook.markdown
    assert "URL-decoded at ingest" in runbook.markdown


def test_backtest_numbers_appear_in_the_expected_trigger_section():
    runbook = generate(_candidate(), _fingerprint(), _decision(), _forecast(), sigma_rule=_sigma_rule())

    trigger = runbook.markdown.split("## Expected trigger")[1]
    assert "**12**" in trigger
    assert "12.0%" in trigger


def test_writes_a_file_when_given_a_directory(tmp_path):
    runbook = generate(_candidate(), _fingerprint(), _decision(), _forecast(),
                       sigma_rule=_sigma_rule(), out_dir=tmp_path)

    assert runbook.markdown_path
    written = Path(runbook.markdown_path)
    assert written.parent == tmp_path
    assert written.read_text(encoding="utf-8") == runbook.markdown


def test_no_file_is_written_without_a_directory():
    runbook = generate(_candidate(), _fingerprint(), _decision(), _forecast(), sigma_rule=_sigma_rule())

    assert runbook.markdown_path == ""
    assert runbook.markdown
