"""Runbook generator tests: field targeting, draft queries, and required sections."""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.rule import SigmaRule

from engine.classification.rule_type_classifier import ElasticRuleType, RuleTypeDecision
from engine.matching.candidate import MatchCandidate, MatchSource
from engine.prediction.backtest import BacktestResult, ConfidenceTier, PredictionResult
from engine.profiling.field_profiler import EventExample, FieldProfile, LogFingerprint
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


def _taxonomy_query(entry: TaxonomyEntry, *, rule_type=ElasticRuleType.CUSTOM_QUERY, **kwargs) -> str:
    candidate = _candidate(
        source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={}
    )
    markdown = generate(
        candidate, _fingerprint(**kwargs), _decision(rule_type), _forecast(), taxonomy_entry=entry
    ).markdown
    return markdown.split("## Draft query")[1].split("```")[1].split("\n", 1)[1].strip()


def test_a_taxonomy_entry_converts_through_the_same_backend_as_a_sigma_rule():
    """Its detection logic is already Sigma; converting it by hand only re-did
    pySigma, and re-did it wrong. See test_regex_logic_converts_to_a_real_query."""
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={
            "waf": {"Source": ["waf"], "Action": ["block", "log"]},
            "condition": "waf",
        },
    )

    runbook = generate(
        _candidate(source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={}),
        _fingerprint(), _decision(), _forecast(), taxonomy_entry=entry,
    )

    assert "```lucene" in runbook.markdown
    assert "Source:waf" in runbook.markdown
    assert "Action:(block OR log)" in runbook.markdown


def test_regex_logic_converts_to_a_real_query():
    """The old hand-rolled KQL emitted `true` here, which matched every event."""
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={"payload": {"Query|re": r"union\s+select"}, "condition": "payload"},
    )

    query = _taxonomy_query(entry)

    assert query == r"Query:/union\s+select/"
    assert "true" not in query


def test_a_comparison_modifier_is_not_flattened_into_equality():
    """`lte` used to be dropped, turning `score <= 20` into `score = 20`."""
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={"low": {"Score|lte": 20}, "condition": "low"},
    )

    assert _taxonomy_query(entry) == "Score:<=20"


def test_a_negated_condition_survives_conversion():
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={
            "low": {"Score|lte": 20},
            "stopped": {"Action": ["block", "challenge"]},
            "condition": "low and not stopped",
        },
    )

    query = _taxonomy_query(entry)

    assert "Score:<=20" in query
    assert "NOT" in query and "Action:(block OR challenge)" in query


def test_contains_becomes_a_wildcard_the_backend_escaped_itself():
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={"sel": {"Query|contains": ["union select"]}, "condition": "sel"},
    )

    assert _taxonomy_query(entry) == r"Query:*union\ select*"


def test_the_rule_type_picks_the_query_language():
    """A taxonomy entry classified EQL used to be rendered as KQL regardless."""
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={"sel": {"Action": ["block"]}, "condition": "sel"},
    )
    candidate = _candidate(source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={})

    markdown = generate(candidate, _fingerprint(), _decision(ElasticRuleType.EQL), _forecast(),
                        taxonomy_entry=entry).markdown

    assert "```eql" in markdown
    assert "any where Action" in markdown


def test_an_entry_whose_logic_is_not_valid_sigma_is_reported_not_hidden():
    entry = TaxonomyEntry(
        slug="test", name="Test entry", confidence=0.8,
        detection_logic={"sel": {"Action": ["block"]}, "condition": "sel and missing_block"},
    )
    candidate = _candidate(source=MatchSource.INTERNAL_TAXONOMY, rule_ref="internal:test", matched_fields={})

    markdown = generate(candidate, _fingerprint(), _decision(), _forecast(),
                        taxonomy_entry=entry).markdown

    assert "Conversion did not produce a query" in markdown
    assert "by hand" in markdown


def test_the_same_entry_always_converts_to_the_same_rule_id():
    """A rule id that moved every run would look like a different rule each time."""
    from engine.runbook.generator import _entry_as_sigma_rule

    entry = TaxonomyEntry(slug="stable-slug", name="Test entry", confidence=0.8,
                          detection_logic={"sel": {"Action": ["block"]}, "condition": "sel"})

    assert str(_entry_as_sigma_rule(entry).id) == str(_entry_as_sigma_rule(entry).id)


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


def test_matched_events_are_shown_not_just_counted():
    """A reviewer checks whether the rule fired for the right reason, not that it did."""
    forecast = _forecast(
        backtest=BacktestResult(
            evaluated=True, total_events=100, matched_events=1, alerts=1, match_rate=0.01,
            example_lines=[7],
            examples=[EventExample(
                line=7,
                timestamp="2026-03-11T09:03:44+00:00",
                raw_timestamp="2026-03-11T09:03:44Z",
                key_fields=[("ClientRequestQuery", "id=1 OR 1=1")],
                other_fields=[("Action", "block")],
                omitted_fields=3,
            )],
        )
    )

    markdown = generate(_candidate(), _fingerprint(), _decision(), forecast,
                        sigma_rule=_sigma_rule()).markdown
    trigger = markdown.split("## Expected trigger")[1]

    assert "### Matched events" in trigger
    assert "id=1 OR 1=1" in trigger
    # The raw form of the time is shown; the ISO reading only when it differs.
    assert "2026-03-11T09:03:44Z" in trigger
    assert "->" not in trigger.split("### Matched events")[1].splitlines()[3]
    # And one event in full, with the fields the wide table left out.
    assert "Line 7 in full" in trigger
    assert "`Action` | `block`" in trigger
    assert "and 3 more field(s)" in trigger


def test_a_reinterpreted_timestamp_shows_both_readings():
    """A day-first date is a reading of the value, and the reader should see both."""
    forecast = _forecast(
        backtest=BacktestResult(
            evaluated=True, total_events=10, matched_events=1, alerts=1, match_rate=0.1,
            examples=[EventExample(
                line=3,
                timestamp="2026-07-16T20:26:12.030000+00:00",
                raw_timestamp="16/07/2026 20:26:12.030",
                key_fields=[("ClientIP", "203.0.113.1")],
            )],
        )
    )

    markdown = generate(_candidate(), _fingerprint(), _decision(), forecast,
                        sigma_rule=_sigma_rule()).markdown

    assert "`16/07/2026 20:26:12.030` -> 2026-07-16T20:26:12.030000+00:00" in markdown


def test_the_event_time_column_is_named_in_the_coverage_table():
    fingerprint = LogFingerprint(
        profiles=[
            FieldProfile(field_name="date", dtype="date", cardinality=1, null_rate=0.0,
                         example="2026-07-14"),
            FieldProfile(field_name="time", dtype="time", cardinality=9, null_rate=0.0,
                         example="01:02:11"),
        ],
        record_count=9,
    )

    markdown = generate(_candidate(), fingerprint, _decision(), _forecast(),
                        sigma_rule=_sigma_rule()).markdown

    assert "| Event time | `date + time` (second granularity) - split across two columns |" in markdown


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
