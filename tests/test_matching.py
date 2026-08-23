"""Sigma matching tests: the logsource gate, the ECS field bridge, and ranking."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.ingestion import parser
from engine.matching import sigma_matcher
from engine.matching.candidate import MatchSource
from engine.matching.sigma_matcher import SigmaRuleEntry, SigmaRuleIndex
from engine.profiling.field_profiler import FieldProfile, LogFingerprint
from engine.storage.db import REPO_ROOT

FIXTURES = Path(__file__).parent / "fixtures"
CLOUDFLARE = FIXTURES / "cloudflare_waf_firewall_events.csv"
SIGMA_CORPUS = REPO_ROOT / "data" / "sigma-corpus" / "rules"


def _cloudflare_fingerprint() -> LogFingerprint:
    """A Cloudflare sample after profiling and ECS gap analysis."""
    return LogFingerprint(
        profiles=[
            FieldProfile(field_name="ClientRequestMethod", dtype="string", cardinality=2, null_rate=0.0,
                         suggested_ecs_field="http.request.method"),
            FieldProfile(field_name="ClientRequestQuery", dtype="string", cardinality=11, null_rate=0.7,
                         suggested_ecs_field="url.query"),
            FieldProfile(field_name="EdgeResponseStatus", dtype="integer", cardinality=5, null_rate=0.0,
                         suggested_ecs_field="http.response.status_code"),
        ],
        inferred_category="webserver",
        inferred_product="cloudflare",
        inferred_service="firewall_events",
        record_count=37,
    )


def _rule(**overrides) -> SigmaRuleEntry:
    defaults = dict(
        id="00000000-0000-0000-0000-000000000001",
        title="Test rule",
        path="rules/web/test.yml",
        category="webserver",
        detection_fields=["cs-method"],
    )
    defaults.update(overrides)
    return SigmaRuleEntry(**defaults)


def _index(*rules: SigmaRuleEntry) -> SigmaRuleIndex:
    return SigmaRuleIndex(corpus_path="test", fingerprint="test", rules=list(rules))


def test_sigma_field_resolves_through_ecs_to_a_vendor_column():
    """The Phase 0 hand trace: cs-method -> http.request.method -> ClientRequestMethod."""
    candidates = sigma_matcher.match(_cloudflare_fingerprint(), _index(_rule()))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.source is MatchSource.SIGMA
    assert candidate.matched_fields == {"cs-method": "ClientRequestMethod"}
    assert candidate.missing_fields == []


def test_rule_for_another_product_is_excluded():
    windows_rule = _rule(category=None, product="windows", service="security", detection_fields=["EventID"])

    assert sigma_matcher.match(_cloudflare_fingerprint(), _index(windows_rule)) == []


def test_rule_pinning_an_unconfirmable_element_is_excluded():
    """The fingerprint has no service for a rule that demands one -> not a candidate."""
    fingerprint = _cloudflare_fingerprint().model_copy(update={"inferred_service": None})
    rule = _rule(service="firewall_events")

    assert sigma_matcher.match(fingerprint, _index(rule)) == []


def test_more_pinned_logsource_elements_score_higher():
    loose = _rule(id="a", title="Loose", category="webserver")
    tight = _rule(id="b", title="Tight", category="webserver", product="cloudflare", service="firewall_events")

    candidates = sigma_matcher.match(_cloudflare_fingerprint(), _index(loose, tight))

    assert [candidate.title for candidate in candidates] == ["Tight", "Loose"]


def test_more_supported_fields_break_the_tie():
    one_field = _rule(id="a", title="One", detection_fields=["cs-method"])
    three_fields = _rule(id="b", title="Three", detection_fields=["cs-method", "cs-uri-query", "sc-status"])

    candidates = sigma_matcher.match(_cloudflare_fingerprint(), _index(one_field, three_fields))

    assert [candidate.title for candidate in candidates] == ["Three", "One"]


def test_missing_fields_are_reported_not_hidden():
    rule = _rule(detection_fields=["cs-method", "cs-cookie"])

    candidate = sigma_matcher.match(_cloudflare_fingerprint(), _index(rule))[0]

    assert candidate.missing_fields == ["cs-cookie"]
    assert candidate.field_coverage == pytest.approx(0.5)
    assert "fields missing" in candidate.reasoning


def test_rule_needing_nothing_available_is_dropped():
    rule = _rule(detection_fields=["cs-cookie", "cs-username"])

    assert sigma_matcher.match(_cloudflare_fingerprint(), _index(rule)) == []


def test_keyword_only_rule_is_feasible_but_ranked_lower():
    keywords_only = _rule(id="a", title="Keywords", detection_fields=[], has_keywords=True)
    fielded = _rule(id="b", title="Fielded", detection_fields=["cs-method"])

    candidates = sigma_matcher.match(_cloudflare_fingerprint(), _index(keywords_only, fielded))

    by_title = {candidate.title: candidate for candidate in candidates}
    assert by_title["Keywords"].uses_full_text_search is True
    assert by_title["Keywords"].confidence < by_title["Fielded"].confidence


def test_mitre_techniques_and_reference_are_carried_through():
    rule = _rule(mitre_techniques=["T1190"], level="high")

    candidate = sigma_matcher.match(_cloudflare_fingerprint(), _index(rule))[0]

    assert candidate.mitre_techniques == ["T1190"]
    assert candidate.level == "high"
    assert candidate.rule_ref == "sigma:00000000-0000-0000-0000-000000000001"


def test_min_confidence_filters():
    rule = _rule()

    assert sigma_matcher.match(_cloudflare_fingerprint(), _index(rule), min_confidence=0.99) == []


@pytest.mark.skipif(not SIGMA_CORPUS.is_dir(), reason="Sigma corpus not cloned; run scripts/setup.ps1")
def test_real_corpus_finds_the_phase_0_rule():
    """End to end against the real corpus: the rule Phase 0 traced by hand."""
    from engine.profiling.data_classifier import classify
    from engine.profiling.field_profiler import build_fingerprint, profile_fields

    sample = parser.parse(CLOUDFLARE)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    for profile in profiles:
        # Stand in for ECS gap analysis so this test does not need the
        # elastic/integrations clone as well.
        if profile.field_name == "ClientRequestMethod":
            profile.suggested_ecs_field = "http.request.method"
        elif profile.field_name == "EdgeResponseStatus":
            profile.suggested_ecs_field = "http.response.status_code"

    fingerprint = build_fingerprint(profiles, classify(sample.field_names), record_count=sample.record_count)
    index = sigma_matcher.load_rule_index()
    assert index is not None

    candidates = sigma_matcher.match(fingerprint, index, min_confidence=0.4)
    references = {candidate.rule_ref for candidate in candidates}

    assert "sigma:5513deaf-f49a-46c2-a6c8-3f111b5cb453" in references, "SQL Injection Strings In URI"
    assert all(candidate.confidence >= 0.4 for candidate in candidates)
