"""Backtest and prediction tests: rule execution, aggregation, volume, tiers."""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.rule import SigmaRule

from engine.ingestion.schemas import LogRecord
from engine.matching.candidate import MatchCandidate, MatchSource
from engine.prediction.backtest import (
    ALERT_VOLUME_CEILING,
    MIN_EVENTS_FOR_NOISE,
    ConfidenceTier,
    backtest,
    predict,
)
from engine.profiling.field_profiler import FieldProfile, LogFingerprint
from engine.storage.taxonomy_store import TaxonomyEntry

FIXTURES = Path(__file__).parent / "fixtures"


def _records(rows: list[dict[str, str]]) -> list[LogRecord]:
    return [LogRecord(line=index + 2, fields=row) for index, row in enumerate(rows)]


def _fingerprint(records: list[LogRecord], *, timestamp_field: str | None = "ts") -> LogFingerprint:
    names: list[str] = []
    for record in records:
        for name in record.fields:
            if name not in names:
                names.append(name)
    profiles = [
        FieldProfile(
            field_name=name,
            dtype="timestamp" if name == timestamp_field else "string",
            cardinality=2,
            null_rate=0.0,
        )
        for name in names
    ]
    return LogFingerprint(profiles=profiles, record_count=len(records))


def _candidate(**overrides) -> MatchCandidate:
    defaults = dict(
        source=MatchSource.SIGMA, rule_ref="sigma:test", confidence=0.8, title="Test", matched_fields={}
    )
    defaults.update(overrides)
    return MatchCandidate(**defaults)


def _rule(detection: str) -> SigmaRule:
    return SigmaRule.from_yaml(
        "title: Test rule\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "status: test\n"
        "logsource:\n"
        "    category: webserver\n"
        f"detection:\n{detection}\n"
    )


def _entry(**overrides) -> TaxonomyEntry:
    defaults = dict(slug="test", name="Test entry", confidence=0.8)
    defaults.update(overrides)
    return TaxonomyEntry(**defaults)


# ------------------------------------------------------------ Sigma execution


def test_runs_a_field_equality_rule():
    rule = _rule("    selection:\n        method: 'POST'\n    condition: selection")
    records = _records([{"method": "GET"}, {"method": "POST"}, {"method": "POST"}])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None), sigma_rule=rule)

    assert result.evaluated is True
    assert result.matched_events == 2
    assert result.match_rate == pytest.approx(2 / 3, abs=0.01)


def test_runs_a_contains_modifier():
    rule = _rule("    selection:\n        uri|contains: 'etc/passwd'\n    condition: selection")
    records = _records([{"uri": "/index.html"}, {"uri": "/../../etc/passwd"}])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None), sigma_rule=rule)

    assert result.matched_events == 1
    assert result.example_lines == [3]


def test_matching_is_case_insensitive_like_sigma():
    rule = _rule("    selection:\n        action: 'BLOCK'\n    condition: selection")
    records = _records([{"action": "block"}])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None), sigma_rule=rule)

    assert result.matched_events == 1


def test_runs_a_fieldless_keyword_search_over_the_whole_event():
    rule = _rule("    keywords:\n        - 'UNION SELECT'\n    condition: keywords")
    records = _records([{"a": "hello", "b": "world"}, {"a": "x", "b": "1 union select 2"}])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None), sigma_rule=rule)

    assert result.matched_events == 1


def test_honours_not_in_the_condition():
    rule = _rule(
        "    selection:\n        method: 'GET'\n"
        "    filter:\n        status: '404'\n"
        "    condition: selection and not filter"
    )
    records = _records([
        {"method": "GET", "status": "200"},
        {"method": "GET", "status": "404"},
        {"method": "POST", "status": "200"},
    ])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None), sigma_rule=rule)

    assert result.matched_events == 1


def test_rule_fields_resolve_through_the_candidate_field_map():
    """The Sigma taxonomy name is bridged to the vendor column, as in matching."""
    rule = _rule("    selection:\n        cs-method: 'POST'\n    condition: selection")
    records = _records([{"ClientRequestMethod": "POST"}, {"ClientRequestMethod": "GET"}])
    candidate = _candidate(matched_fields={"cs-method": "ClientRequestMethod"})

    result = backtest(candidate, records, _fingerprint(records, timestamp_field=None), sigma_rule=rule)

    assert result.matched_events == 1


def test_missing_detection_logic_is_reported_not_guessed():
    records = _records([{"a": "1"}])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None))

    assert result.evaluated is False
    assert "no detection logic" in result.unsupported_reason


# --------------------------------------------------------- taxonomy execution


def test_runs_a_taxonomy_selection_block():
    entry = _entry(detection_logic={"selection": {"Action": ["block"]}, "condition": "selection"})
    records = _records([{"Action": "block"}, {"Action": "allow"}])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None),
                      taxonomy_entry=entry)

    assert result.matched_events == 1


def test_runs_a_taxonomy_or_condition():
    entry = _entry(detection_logic={
        "waf": {"Source": ["waf"]},
        "payload": {"Query|contains": ["union select"]},
        "condition": "waf or payload",
    })
    records = _records([
        {"Source": "waf", "Query": "?a=1"},
        {"Source": "unknown", "Query": "?a=1 UNION SELECT 2"},
        {"Source": "unknown", "Query": "?a=1"},
    ])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None),
                      taxonomy_entry=entry)

    assert result.matched_events == 2


def test_runs_a_taxonomy_regex_modifier():
    entry = _entry(detection_logic={
        "payload": {"Query|re": r"(?i)\bor\b\s+1\s*=\s*1"},
        "condition": "payload",
    })
    records = _records([{"Query": "?id=8812 OR 1=1--"}, {"Query": "?id=8812"}])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None),
                      taxonomy_entry=entry)

    assert result.matched_events == 1


def test_taxonomy_condition_referencing_an_unknown_block_is_refused():
    entry = _entry(detection_logic={"selection": {"a": "1"}, "condition": "selection and ghost"})
    records = _records([{"a": "1"}])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None),
                      taxonomy_entry=entry)

    assert result.evaluated is False
    assert "unknown block 'ghost'" in result.unsupported_reason


def test_taxonomy_condition_cannot_smuggle_in_code():
    """The condition is walked as an AST; anything executable is refused."""
    entry = _entry(detection_logic={"selection": {"a": "1"}, "condition": "__import__('os').getcwd()"})
    records = _records([{"a": "1"}])

    result = backtest(_candidate(), records, _fingerprint(records, timestamp_field=None),
                      taxonomy_entry=entry)

    assert result.evaluated is False


# --------------------------------------------------------------- aggregation


def test_threshold_aggregation_collapses_events_into_alerts():
    """20 failed logins is one alert, not twenty."""
    entry = _entry(detection_logic={
        "failed": {"status": ["401"]},
        "aggregation": {"group_by": ["ip"], "count_gte": 5, "window": "5m"},
        "condition": "failed",
    })
    records = _records([
        {"ip": "10.0.0.1", "status": "401", "ts": f"2026-06-01T00:00:{second:02d}Z"}
        for second in range(6)
    ])

    result = backtest(_candidate(), records, _fingerprint(records), taxonomy_entry=entry)

    assert result.matched_events == 6
    assert result.alerts == 1
    assert "collapse to 1 alert" in result.aggregation_note


def test_threshold_not_reached_produces_no_alert():
    entry = _entry(detection_logic={
        "failed": {"status": ["401"]},
        "aggregation": {"group_by": ["ip"], "count_gte": 20, "window": "5m"},
        "condition": "failed",
    })
    records = _records([
        {"ip": "10.0.0.1", "status": "401", "ts": f"2026-06-01T00:00:{second:02d}Z"}
        for second in range(6)
    ])

    result = backtest(_candidate(), records, _fingerprint(records), taxonomy_entry=entry)

    assert result.matched_events == 6
    assert result.alerts == 0


def test_separate_groups_alert_separately():
    entry = _entry(detection_logic={
        "failed": {"status": ["401"]},
        "aggregation": {"group_by": ["ip"], "count_gte": 2, "window": "1h"},
        "condition": "failed",
    })
    rows = []
    for address in ("10.0.0.1", "10.0.0.2"):
        rows += [
            {"ip": address, "status": "401", "ts": f"2026-06-01T00:0{index}:00Z"} for index in range(2)
        ]

    result = backtest(_candidate(), _records(rows), _fingerprint(_records(rows)), taxonomy_entry=entry)

    assert result.alerts == 2


# --------------------------------------------------------- volume and tiers


def _many_records(count: int, *, matching: int, minutes_apart: int = 1) -> list[LogRecord]:
    rows = []
    for index in range(count):
        minute = (index * minutes_apart) % 60
        hour = (index * minutes_apart) // 60
        rows.append({
            "status": "401" if index < matching else "200",
            "ts": f"2026-06-01T{hour:02d}:{minute:02d}:00Z",
        })
    return _records(rows)


def _threshold_free_entry() -> TaxonomyEntry:
    return _entry(detection_logic={"failed": {"status": ["401"]}, "condition": "failed"})


def test_volume_projects_from_a_stated_log_rate():
    records = _many_records(200, matching=2)
    forecast = predict(
        _candidate(), records, _fingerprint(records),
        taxonomy_entry=_threshold_free_entry(), log_rate_per_day=100_000,
    )

    assert forecast.projection_basis == "client log rate"
    assert forecast.estimated_alert_volume == pytest.approx(1000.0, rel=0.01)


def test_volume_projects_from_the_sample_span_when_no_rate_is_given():
    records = _many_records(200, matching=2)  # spans 200 minutes
    forecast = predict(
        _candidate(), records, _fingerprint(records), taxonomy_entry=_threshold_free_entry()
    )

    assert forecast.projection_basis == "sample time span"
    assert forecast.estimated_alert_volume > 0


def test_short_sample_projection_is_labelled_unreliable():
    records = _records([
        {"status": "401", "ts": "2026-06-01T00:00:00Z"},
        {"status": "401", "ts": "2026-06-01T00:05:00Z"},
    ])

    forecast = predict(
        _candidate(), records, _fingerprint(records), taxonomy_entry=_threshold_free_entry()
    )

    assert "UNRELIABLE" in forecast.notes
    assert forecast.confidence_tier is not ConfidenceTier.HIGH


def test_noise_is_not_judged_on_a_tiny_sample():
    """Two hits in a handful of events is not a 5% match rate worth acting on."""
    records = _records([{"status": "401"}, {"status": "200"}])

    forecast = predict(
        _candidate(), records, _fingerprint(records, timestamp_field=None),
        taxonomy_entry=_threshold_free_entry(),
    )

    assert forecast.noisy is False
    assert f"{MIN_EVENTS_FOR_NOISE} events" in forecast.notes


def test_noisy_rule_on_a_real_sized_sample_is_flagged_and_downgraded():
    records = _many_records(200, matching=100)  # 50% of events

    forecast = predict(
        _candidate(), records, _fingerprint(records), taxonomy_entry=_threshold_free_entry()
    )

    assert forecast.noisy is True
    assert forecast.confidence_tier is ConfidenceTier.LOW
    assert "POTENTIALLY NOISY" in forecast.notes


def test_unworkable_projected_volume_is_flagged():
    records = _many_records(200, matching=20)
    forecast = predict(
        _candidate(), records, _fingerprint(records),
        taxonomy_entry=_threshold_free_entry(), log_rate_per_day=1_000_000,
    )

    assert forecast.estimated_alert_volume > ALERT_VOLUME_CEILING
    assert "UNWORKABLE VOLUME" in forecast.notes
    assert forecast.confidence_tier is ConfidenceTier.LOW


def test_missing_fields_force_a_low_tier():
    records = _many_records(200, matching=2)
    candidate = _candidate(missing_fields=["SomethingAbsent"])

    forecast = predict(candidate, records, _fingerprint(records),
                       taxonomy_entry=_threshold_free_entry(), log_rate_per_day=1000)

    assert forecast.confidence_tier is ConfidenceTier.LOW


def test_zero_matches_is_unproven_not_failed():
    records = _many_records(200, matching=0)

    forecast = predict(_candidate(), records, _fingerprint(records),
                       taxonomy_entry=_threshold_free_entry(), log_rate_per_day=1000)

    assert forecast.confidence_tier is ConfidenceTier.MEDIUM
    assert "feasible but unproven" in forecast.notes


def test_high_tier_needs_a_trustworthy_projection():
    records = _many_records(200, matching=2)

    forecast = predict(_candidate(confidence=0.85), records, _fingerprint(records),
                       taxonomy_entry=_threshold_free_entry(), log_rate_per_day=1000)

    assert forecast.confidence_tier is ConfidenceTier.HIGH
    assert forecast.estimated_alert_volume == pytest.approx(10.0, rel=0.01)


def test_unevaluated_candidate_is_low_and_says_why():
    records = _many_records(200, matching=2)
    entry = _entry(detection_logic={"selection": {"a": "1"}, "condition": "selection and ghost"})

    forecast = predict(_candidate(), records, _fingerprint(records), taxonomy_entry=entry)

    assert forecast.confidence_tier is ConfidenceTier.LOW
    assert forecast.estimated_alert_volume == 0.0
    assert "Not backtested" in forecast.notes


# --------------------------------------------------------------- end to end


def test_seed_entry_reproduces_the_phase_0_hand_count():
    """The SQLi entry caught 5 of 5 attempts by hand in Phase 0; the engine must agree."""
    from engine.ingestion import parser
    from engine.matching import taxonomy_matcher
    from engine.profiling.data_classifier import classify
    from engine.profiling.field_profiler import build_fingerprint, profile_fields
    from engine.storage.taxonomy_store import load_entries_from_json
    from scripts.seed_taxonomy import DEFAULT_SEED_FILE

    sample = parser.parse(FIXTURES / "cloudflare_waf_firewall_events.csv")
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    fingerprint = build_fingerprint(
        profiles, classify(sample.field_names), record_count=sample.record_count
    )
    entries = {entry.slug: entry for entry in load_entries_from_json(DEFAULT_SEED_FILE)}
    candidates = {
        candidate.rule_ref: candidate
        for candidate in taxonomy_matcher.match(fingerprint, list(entries.values()))
    }

    result = backtest(
        candidates["internal:cloudflare-waf-sqli"],
        sample.records,
        fingerprint,
        taxonomy_entry=entries["cloudflare-waf-sqli"],
    )

    assert result.evaluated is True
    assert result.matched_events == 5
    assert result.example_lines == [6, 7, 8, 9, 10]
