"""Rule type classifier tests: every row of the BLUEPRINT 5.4 decision table."""

from __future__ import annotations

import pytest

from engine.classification.rule_type_classifier import (
    ElasticRuleType,
    classify,
    intel_matchable_entities,
)
from engine.matching.candidate import MatchCandidate, MatchSource
from engine.profiling.entity_recognition import EntityType
from engine.profiling.field_profiler import FieldProfile, LogFingerprint
from engine.storage.taxonomy_store import TaxonomyEntry


def _candidate(**overrides) -> MatchCandidate:
    defaults = dict(
        source=MatchSource.SIGMA,
        rule_ref="sigma:test",
        confidence=0.8,
        title="Test candidate",
    )
    defaults.update(overrides)
    return MatchCandidate(**defaults)


def _fingerprint(*, entities: list[EntityType] | None = None, timestamp: bool = True,
                 record_count: int = 500) -> LogFingerprint:
    profiles = [
        FieldProfile(field_name=f"field_{index}", dtype="string", cardinality=5, null_rate=0.0,
                     entity_type=entity)
        for index, entity in enumerate(entities or [])
    ]
    if timestamp:
        profiles.append(
            FieldProfile(field_name="ts", dtype="timestamp", cardinality=10, null_rate=0.0)
        )
    return LogFingerprint(profiles=profiles, record_count=record_count)


def _entry(**overrides) -> TaxonomyEntry:
    defaults = dict(slug="test-entry", name="Test entry", confidence=0.7)
    defaults.update(overrides)
    return TaxonomyEntry(**defaults)


# ------------------------------------------- BLUEPRINT 5.4 decision table rows


def test_row1_simple_field_match_is_custom_query():
    decision = classify(_candidate(), _fingerprint())

    assert decision.elastic_type is ElasticRuleType.CUSTOM_QUERY
    assert "single event" in decision.reasoning


def test_row2_event_sequence_is_eql():
    entry = _entry(detection_logic={"sequence": [{"a": 1}, {"b": 2}], "condition": "sequence"})

    decision = classify(_candidate(), _fingerprint(entities=[EntityType.USER]), taxonomy_entry=entry)

    assert decision.elastic_type is ElasticRuleType.EQL
    assert decision.hunting_technique.startswith("Behavioral Analysis")


def test_row3_volume_count_is_threshold():
    entry = _entry(detection_logic={"aggregation": {"count_gte": 20, "group_by": ["ip"]}})

    decision = classify(_candidate(), _fingerprint(entities=[EntityType.IP]), taxonomy_entry=entry)

    assert decision.elastic_type is ElasticRuleType.THRESHOLD
    assert "Trend & Statistical Analysis" in decision.hunting_technique


def test_row4_computed_aggregation_is_esql():
    entry = _entry(detection_logic={"stats": {"by": ["user"], "eval": "ratio"}})

    decision = classify(_candidate(), _fingerprint(entities=[EntityType.USER]), taxonomy_entry=entry)

    assert decision.elastic_type is ElasticRuleType.ESQL


def test_row5_indicator_join_is_indicator_match():
    entry = _entry(detection_logic={"indicator": {"field": "ip", "list": "ti-index"}})

    decision = classify(_candidate(), _fingerprint(entities=[EntityType.IP]), taxonomy_entry=entry)

    assert decision.elastic_type is ElasticRuleType.INDICATOR_MATCH
    assert any("indicator index" in caveat for caveat in decision.caveats)


def test_row6_first_seen_is_new_terms():
    entry = _entry(detection_logic={"first_seen": {"field": "user.name"}})

    decision = classify(_candidate(), _fingerprint(entities=[EntityType.USER]), taxonomy_entry=entry)

    assert decision.elastic_type is ElasticRuleType.NEW_TERMS
    assert "Anomaly Detection" in decision.hunting_technique


def test_row7_adaptive_baseline_is_machine_learning():
    entry = _entry(detection_logic={"baseline": {"window": "30d"}})

    decision = classify(_candidate(), _fingerprint(entities=[EntityType.IP]), taxonomy_entry=entry)

    assert decision.elastic_type is ElasticRuleType.MACHINE_LEARNING
    assert any("licence" in caveat for caveat in decision.caveats)


# ------------------------------------------------------------------ resolution


def test_simplest_sufficient_type_wins():
    """BLUEPRINT 5.4: prefer the least complex type that is enough."""
    entry = _entry(detection_logic={"selection": {"a": 1}, "condition": "selection"})

    decision = classify(_candidate(), _fingerprint(), taxonomy_entry=entry)

    assert decision.elastic_type is ElasticRuleType.CUSTOM_QUERY


def test_sequence_plus_count_needs_esql():
    """Threshold cannot order events and EQL cannot count them; only ES|QL does both."""
    entry = _entry(detection_logic={"sequence": [], "aggregation": {"count_gte": 5}})

    decision = classify(_candidate(), _fingerprint(entities=[EntityType.IP]), taxonomy_entry=entry)

    assert decision.elastic_type is ElasticRuleType.ESQL


def test_curator_suggestion_is_honoured_without_explicit_logic():
    entry = _entry(suggested_rule_type="threshold", detection_logic={"selection": {"a": 1}})

    decision = classify(_candidate(), _fingerprint(entities=[EntityType.IP]), taxonomy_entry=entry)

    assert decision.elastic_type is ElasticRuleType.THRESHOLD
    assert "curator" in decision.reasoning


# ----------------------------------------------------------------- alternatives


def test_brute_force_technique_offers_threshold_as_an_alternative():
    candidate = _candidate(mitre_techniques=["T1110.004"])

    decision = classify(candidate, _fingerprint(entities=[EntityType.IP]))

    assert decision.elastic_type is ElasticRuleType.CUSTOM_QUERY
    assert ElasticRuleType.THRESHOLD in decision.alternatives


def test_valid_account_technique_offers_new_terms():
    candidate = _candidate(mitre_techniques=["T1078.002"])

    decision = classify(candidate, _fingerprint(entities=[EntityType.USER]))

    assert ElasticRuleType.NEW_TERMS in decision.alternatives


def test_indicator_match_is_not_offered_per_candidate():
    """An IP in the log does not make every rule an indicator match rule."""
    decision = classify(_candidate(), _fingerprint(entities=[EntityType.IP, EntityType.DOMAIN]))

    assert ElasticRuleType.INDICATOR_MATCH not in decision.alternatives


def test_intel_matchable_entities_are_reported_at_sample_level():
    fingerprint = _fingerprint(entities=[EntityType.IP, EntityType.DOMAIN, EntityType.USER])

    assert intel_matchable_entities(fingerprint) == [EntityType.DOMAIN, EntityType.IP]


def test_alternatives_are_ordered_simplest_first():
    candidate = _candidate(mitre_techniques=["T1110", "T1078"])

    decision = classify(candidate, _fingerprint(entities=[EntityType.USER]))

    assert decision.alternatives == [ElasticRuleType.THRESHOLD, ElasticRuleType.NEW_TERMS]


# --------------------------------------------------------------------- caveats


def test_windowed_rule_without_a_timestamp_is_caveated():
    entry = _entry(detection_logic={"aggregation": {"count_gte": 10}})

    decision = classify(_candidate(), _fingerprint(timestamp=False, entities=[EntityType.IP]),
                        taxonomy_entry=entry)

    assert any("timestamp" in caveat for caveat in decision.caveats)


def test_windowed_rule_without_a_groupable_entity_is_caveated():
    entry = _entry(detection_logic={"aggregation": {"count_gte": 10}})

    decision = classify(_candidate(), _fingerprint(entities=[]), taxonomy_entry=entry)

    assert any("group events by" in caveat for caveat in decision.caveats)


def test_first_seen_rule_names_the_sample_size_it_cannot_baseline_from():
    entry = _entry(detection_logic={"new_terms": {"field": "user.name"}})

    decision = classify(_candidate(), _fingerprint(record_count=37, entities=[EntityType.USER]),
                        taxonomy_entry=entry)

    assert any("37 events" in caveat for caveat in decision.caveats)


def test_simple_query_has_no_caveats():
    decision = classify(_candidate(), _fingerprint())

    assert decision.caveats == []


@pytest.mark.parametrize(
    "rule_type",
    [ElasticRuleType.EQL, ElasticRuleType.THRESHOLD, ElasticRuleType.ESQL,
     ElasticRuleType.INDICATOR_MATCH, ElasticRuleType.NEW_TERMS, ElasticRuleType.MACHINE_LEARNING],
)
def test_every_non_trivial_type_maps_to_a_hunting_technique(rule_type):
    """BLUEPRINT 5.4 ties each rule type to a threat-hunting technique category."""
    from engine.classification.rule_type_classifier import _HUNTING_TECHNIQUE

    assert _HUNTING_TECHNIQUE[rule_type]
