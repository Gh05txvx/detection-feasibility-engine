"""Hypothesis module tests: ABLE selection, the four checks, and the report."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.hypothesis.able import UNCLASSIFIED_HYPOTHESIS, EvidenceRequirement, build_hypotheses
from engine.hypothesis.report import (
    VERDICT_FEASIBLE_NO_RULE,
    VERDICT_REJECTED,
    build_report,
    hypothesis_filename,
    render_hypothesis_markdown,
    render_markdown,
)
from engine.hypothesis.validator import (
    CheckStatus,
    build_context,
    resolve_evidence,
    validate,
)
from engine.ingestion import parser
from engine.ingestion.schemas import LogRecord
from engine.matching.sigma_matcher import SigmaRuleEntry, SigmaRuleIndex
from engine.profiling.data_classifier import DataCategory
from engine.profiling.entity_recognition import EntityType
from engine.profiling.field_profiler import FieldProfile, LogFingerprint

FIXTURES = Path(__file__).parent / "fixtures"
APPLIANCE = FIXTURES / "minimal_appliance_syslog.csv"


def _fingerprint(profiles: list[FieldProfile], **overrides) -> LogFingerprint:
    defaults = dict(
        profiles=profiles,
        data_category=DataCategory.AUTHENTICATION_LOGS,
        record_count=len(profiles) and 20,
    )
    defaults.update(overrides)
    return LogFingerprint(**defaults)


def _profile(name: str, **overrides) -> FieldProfile:
    defaults = dict(field_name=name, dtype="string", cardinality=5, null_rate=0.0)
    defaults.update(overrides)
    return FieldProfile(**defaults)


def _records(count: int, start_hour: int = 0, field: str = "timestamp") -> list[LogRecord]:
    return [
        LogRecord(line=index + 2, fields={field: f"2026-06-11T{start_hour + index // 60:02d}:{index % 60:02d}:05Z"})
        for index in range(count)
    ]


def _sigma_index(*techniques: str) -> SigmaRuleIndex:
    rules = [
        SigmaRuleEntry(
            id=f"rule-{index}", title=f"Rule {index}", path="rules/x.yml",
            category="windows", mitre_techniques=[technique],
        )
        for index, technique in enumerate(techniques)
    ]
    return SigmaRuleIndex(corpus_path="test", fingerprint="test", rules=rules)


# ------------------------------------------------------------- ABLE selection


def test_data_category_picks_the_hypotheses():
    fingerprint = _fingerprint([_profile("user")], data_category=DataCategory.DNS_LOGS)

    hypotheses = build_hypotheses(fingerprint)

    assert hypotheses
    assert all("T1071.004" in h.mitre_techniques or "T1568.002" in h.mitre_techniques for h in hypotheses)


def test_authentication_logs_get_credential_abuse_first():
    """BLUEPRINT 5.2: authentication logs imply credential abuse hypotheses."""
    fingerprint = _fingerprint([_profile("user")], data_category=DataCategory.AUTHENTICATION_LOGS)

    hypotheses = build_hypotheses(fingerprint)

    assert "T1110" in hypotheses[0].mitre_techniques


def test_unclassified_sample_gets_the_placeholder_not_a_guess():
    fingerprint = _fingerprint([_profile("colA")], data_category=None)

    hypotheses = build_hypotheses(fingerprint)

    assert len(hypotheses) == 1
    assert hypotheses[0].behavior == UNCLASSIFIED_HYPOTHESIS.behavior
    assert hypotheses[0].mitre_techniques == []


def test_location_names_the_source_and_sample_size():
    fingerprint = _fingerprint(
        [_profile("user")], inferred_product="windows", inferred_service="security", record_count=42
    )

    location = build_hypotheses(fingerprint)[0].location

    assert "windows" in location and "security" in location and "42 events" in location


# ------------------------------------------------------------ evidence lookup


def test_evidence_resolves_by_ecs_before_name():
    requirement = EvidenceRequirement(
        label="source address", ecs_fields=["source.ip"], name_keywords=["ipaddress"]
    )
    fingerprint = _fingerprint([
        _profile("IpAddress"),
        _profile("ClientIP", suggested_ecs_field="source.ip"),
    ])

    resolution = resolve_evidence([requirement], fingerprint)[0]

    assert resolution.field_name == "ClientIP"
    assert resolution.matched_by == "ecs field"


def test_evidence_falls_back_to_entity_then_name():
    by_entity = EvidenceRequirement(label="address", entity_types=[EntityType.IP])
    fingerprint = _fingerprint([_profile("weird_column", entity_type=EntityType.IP)])
    assert resolve_evidence([by_entity], fingerprint)[0].matched_by == "entity type"

    by_name = EvidenceRequirement(label="user", name_keywords=["username"])
    fingerprint = _fingerprint([_profile("UserName")])
    assert resolve_evidence([by_name], fingerprint)[0].matched_by == "field name"


def test_unsatisfiable_evidence_is_reported_as_missing():
    requirement = EvidenceRequirement(label="command line", name_keywords=["cmdline"])
    fingerprint = _fingerprint([_profile("host")])

    assert resolve_evidence([requirement], fingerprint)[0].satisfied is False


# -------------------------------------------------------------------- checks


def _validate(fingerprint, hypothesis, records=None, sigma_index=None, taxonomy=None):
    context = build_context(fingerprint, records)
    checks = validate(
        hypothesis, fingerprint, context=context, sigma_index=sigma_index, taxonomy_techniques=taxonomy
    )
    return {check.name: check for check in checks}


def test_reassess_fails_and_names_what_is_missing():
    fingerprint = _fingerprint([_profile("host"), _profile("timestamp", dtype="timestamp")],
                               data_category=DataCategory.SYSTEM_LOGS)
    hypothesis = build_hypotheses(fingerprint)[0]

    check = _validate(fingerprint, hypothesis)["reassess_data_patterns"]

    assert check.status is CheckStatus.FAIL
    assert check.passed is False
    assert "user identity" in check.missing


def test_reassess_points_at_a_free_text_field_when_one_exists():
    fingerprint = _fingerprint(
        [_profile("host"), _profile("message", example="x" * 100, cardinality=17)],
        data_category=DataCategory.SYSTEM_LOGS,
    )
    hypothesis = build_hypotheses(fingerprint)[0]

    check = _validate(fingerprint, hypothesis)["reassess_data_patterns"]

    assert "message" in check.detail
    assert "without new log data" in check.detail


def test_baseline_check_is_not_applicable_for_per_event_behavior():
    fingerprint = _fingerprint([_profile("host")], data_category=DataCategory.SYSTEM_LOGS)
    hypothesis = build_hypotheses(fingerprint)[0]  # persistence, custom_query

    check = _validate(fingerprint, hypothesis)["confirm_baselines"]

    assert check.status is CheckStatus.NOT_APPLICABLE
    # Not applicable is not a pass, but it is not a failure either.
    assert check.passed is True


def test_baseline_check_fails_on_a_short_sample():
    fingerprint = _fingerprint(
        [_profile("user"), _profile("timestamp", dtype="timestamp"), _profile("srcip", entity_type=EntityType.IP)],
        data_category=DataCategory.AUTHENTICATION_LOGS,
        record_count=20,
    )
    hypothesis = build_hypotheses(fingerprint)[1]  # T1078, needs_baseline

    check = _validate(fingerprint, hypothesis, records=_records(20))["confirm_baselines"]

    assert check.status is CheckStatus.FAIL
    assert "20 events" in check.detail


def test_correlate_passes_and_says_no_rule_targets_this_source():
    fingerprint = _fingerprint([_profile("user")], inferred_product="acme_vpn")
    hypothesis = build_hypotheses(fingerprint)[0]  # T1110

    check = _validate(fingerprint, hypothesis, sigma_index=_sigma_index("T1110", "T1110"))["correlate_threat_intel"]

    assert check.status is CheckStatus.PASS
    assert "2 Sigma rule" in check.detail
    assert "None of them target this log source" in check.detail


def test_correlate_fails_when_nothing_local_covers_the_technique():
    fingerprint = _fingerprint([_profile("user")])
    hypothesis = build_hypotheses(fingerprint)[0]

    check = _validate(fingerprint, hypothesis, sigma_index=_sigma_index("T9999"))["correlate_threat_intel"]

    assert check.status is CheckStatus.FAIL
    assert check.missing


def test_correlate_counts_the_internal_taxonomy_too():
    fingerprint = _fingerprint([_profile("user")])
    hypothesis = build_hypotheses(fingerprint)[0]

    check = _validate(
        fingerprint, hypothesis, sigma_index=_sigma_index("T9999"), taxonomy={"T1110"}
    )["correlate_threat_intel"]

    assert check.status is CheckStatus.PASS
    assert "taxonomy" in check.detail


def test_split_event_time_is_an_ingest_ask_not_a_missing_field():
    """The client already sends the timestamp; asking them to add one is wrong."""
    profiles = [
        _profile("date", dtype="date", example="2026-07-14"),
        _profile("time", dtype="time", example="01:02:11"),
        _profile("user"),
        _profile("status"),
        _profile("srcip", entity_type=EntityType.IP),
    ]
    fingerprint = _fingerprint(profiles, data_category=DataCategory.AUTHENTICATION_LOGS,
                               record_count=20)
    records = [
        LogRecord(line=index + 2, fields={"date": "2026-07-14", "time": f"01:{index:02d}:11"})
        for index in range(20)
    ]

    report = build_report("sample.csv", fingerprint, records=records,
                          sigma_index=_sigma_index("T1110"))

    check = {c.name: c for c in report.reports[0].checks}["contextual_filtering"]
    assert check.status is CheckStatus.PASS
    assert "combine them into @timestamp" in check.detail
    assert "event timestamp" not in report.onboarding_requirements
    assert any("into @timestamp during ingest" in item for item in report.onboarding_requirements)


def test_contextual_filtering_fails_without_a_timestamp():
    fingerprint = _fingerprint(
        [_profile("user"), _profile("status"), _profile("srcip", entity_type=EntityType.IP)],
        data_category=DataCategory.AUTHENTICATION_LOGS,
    )
    hypothesis = build_hypotheses(fingerprint)[0]  # threshold

    check = _validate(fingerprint, hypothesis)["contextual_filtering"]

    assert check.status is CheckStatus.FAIL
    assert "event timestamp" in check.missing


def test_contextual_filtering_fails_when_the_window_does_not_fit():
    profiles = [
        _profile("user"), _profile("status"),
        _profile("srcip", entity_type=EntityType.IP),
        _profile("timestamp", dtype="timestamp"),
    ]
    fingerprint = _fingerprint(profiles, data_category=DataCategory.AUTHENTICATION_LOGS, record_count=10)
    hypothesis = build_hypotheses(fingerprint)[0]  # threshold, 5-minute window

    # Ten events one second apart span far less than a detection window.
    records = [LogRecord(line=i, fields={"timestamp": f"2026-06-11T03:00:{i:02d}Z"}) for i in range(10)]
    check = _validate(fingerprint, hypothesis, records=records)["contextual_filtering"]

    assert check.status is CheckStatus.FAIL
    assert "threshold" in check.detail


# -------------------------------------------------------------------- report


def test_verdict_is_rejected_when_a_check_fails():
    fingerprint = _fingerprint([_profile("host")], data_category=DataCategory.SYSTEM_LOGS)

    report = build_report("sample.csv", fingerprint, sigma_index=_sigma_index("T1543"))

    assert all(item.verdict == VERDICT_REJECTED for item in report.reports)
    assert report.onboarding_requirements


def test_verdict_is_feasible_when_everything_passes():
    """All checks passing means the data supports it and only the rule is missing."""
    profiles = [
        _profile("url_path"), _profile("query"), _profile("status"),
        _profile("srcip", entity_type=EntityType.IP),
        _profile("timestamp", dtype="timestamp"),
        _profile("method"),
    ]
    fingerprint = _fingerprint(profiles, data_category=DataCategory.APPLICATION_LOGS, record_count=500)
    records = _records(500)

    report = build_report(
        "sample.csv", fingerprint, records=records, sigma_index=_sigma_index("T1190", "T1110.004")
    )
    exploitation = report.reports[0]

    assert exploitation.verdict == VERDICT_FEASIBLE_NO_RULE
    assert "encode it back into the internal taxonomy" in (exploitation.remediation or "")


def test_onboarding_requirements_are_deduplicated():
    fingerprint = _fingerprint([_profile("host")], data_category=DataCategory.SYSTEM_LOGS)

    report = build_report("sample.csv", fingerprint, sigma_index=_sigma_index("T1543", "T1070"))

    # Both system-log hypotheses miss the same fields, and the contextual check
    # misses the timestamp again. Each gap is asked for once, in first-seen order.
    assert report.onboarding_requirements == ["outcome or status", "user identity", "event timestamp"]
    assert len(report.reports) == 2


def test_markdown_contains_the_sections_a_reviewer_needs():
    fingerprint = _fingerprint([_profile("host")], data_category=DataCategory.SYSTEM_LOGS)
    report = build_report("sample.csv", fingerprint, sigma_index=_sigma_index("T1543"))

    markdown = render_markdown(report)

    for heading in ("# Detection feasibility: rejection report", "## Why matching returned nothing",
                    "| ABLE | |", "| Validation step | Result | Detail |",
                    "## Onboarding requirements", "## Next step"):
        assert heading in markdown
    assert "not the same as not detectable" in markdown
    assert "analyst review" in markdown.lower()


def test_a_single_hypothesis_renders_as_a_standalone_document():
    """It arrives detached from everything around it, so it repeats the context."""
    fingerprint = _fingerprint([_profile("host")], data_category=DataCategory.SYSTEM_LOGS,
                               inferred_product="acme_vpn", record_count=18)
    report = build_report("vpn-sample.csv", fingerprint, sigma_index=_sigma_index("T1543"))

    markdown = render_hypothesis_markdown(report, 0)
    first, second = report.reports[0], report.reports[1]

    assert markdown.startswith(f"# Detection feasibility: {first.hypothesis.behavior}")
    assert "vpn-sample.csv" in markdown
    assert "acme_vpn" in markdown
    assert "18 events" in markdown
    assert "not the same as not detectable" in markdown
    assert "| ABLE | |" in markdown
    assert "## Validation" in markdown
    assert "## What this needs" in markdown
    assert "Analyst review" in markdown
    # And nothing about the hypothesis it was not asked for.
    assert second.hypothesis.behavior not in markdown


def test_the_report_names_the_field_that_is_missing_not_just_the_verdict():
    """'Rejected' is the verdict; the missing field is what goes to the client."""
    fingerprint = _fingerprint([_profile("host")], data_category=DataCategory.SYSTEM_LOGS)
    report = build_report("sample.csv", fingerprint, sigma_index=_sigma_index("T1543"))
    item = report.reports[0]

    assert item.evidence, "the resolutions have to survive onto the report to be shown"
    assert [gap.label for gap in item.missing_evidence]
    assert all(gap.field_name is None for gap in item.missing_evidence)
    assert any(gap.field_name == "host" for gap in item.present_evidence)

    markdown = render_markdown(report)
    assert "| Evidence | Sample field | Matched by | Status |" in markdown
    assert "**MISSING**" in markdown
    assert "**Rejected.** The sample carries no field for" in markdown
    for gap in item.missing_evidence:
        assert gap.label in markdown


def test_a_rejection_that_is_not_about_a_missing_field_says_so():
    """Not every rejection is a field gap; calling one a field gap misdirects the ask."""
    profiles = [
        _profile("user"), _profile("host"), _profile("action"), _profile("status"),
        _profile("src_ip", entity_type=EntityType.IP),
        _profile("timestamp", dtype="timestamp", example="2026-06-11T03:02:14Z"),
    ]
    fingerprint = _fingerprint(profiles, data_category=DataCategory.AUTHENTICATION_LOGS,
                               record_count=6)
    report = build_report("tiny.csv", fingerprint, records=_records(6))

    rejected = [
        item for item in report.reports
        if item.verdict == VERDICT_REJECTED and not item.missing_evidence
    ]
    assert rejected, "a six-event sample cannot support a baseline even when every field is there"
    for item in rejected:
        assert item.rejection_reason.startswith("Every field this hypothesis needs is present")
        assert "What the sample does not give is" in item.rejection_reason
        # And the field table still renders, showing that they are all present.
        assert "**MISSING**" not in "\n".join(render_hypothesis_markdown(report, 0).splitlines())


def test_the_report_shows_real_events_from_the_sample():
    """The gaps are only judgeable next to what the data does carry."""
    sample = parser.parse(APPLIANCE)
    profiles = [_profile("host"), _profile("severity"), _profile("message"),
                _profile("timestamp", dtype="timestamp", example="2026-06-11T03:02:14Z")]
    fingerprint = _fingerprint(profiles, data_category=DataCategory.SYSTEM_LOGS,
                               record_count=sample.record_count)

    report = build_report("sample.csv", fingerprint, records=sample.records,
                          sigma_index=_sigma_index("T1543"))

    assert len(report.examples) == 5
    assert report.examples[0].line == 2
    assert report.examples[0].timestamp is not None

    markdown = render_markdown(report)
    assert "Example events from the sample" in markdown
    assert "vpn-gw-01" in markdown
    # And it travels with the single-hypothesis export, which stands alone.
    assert "vpn-gw-01" in render_hypothesis_markdown(report, 0)


def test_a_single_hypothesis_carries_only_its_own_requirements():
    fingerprint = _fingerprint([_profile("host")], data_category=DataCategory.SYSTEM_LOGS)
    report = build_report("sample.csv", fingerprint, sigma_index=_sigma_index("T1543"))

    markdown = render_hypothesis_markdown(report, 0)

    for requirement in report.reports[0].requirements:
        assert requirement in markdown


def test_a_single_hypothesis_still_carries_the_sample_wide_ingest_ask():
    """Splitting event time is the source's problem, not one hypothesis's."""
    profiles = [
        _profile("date", dtype="date", example="2026-07-14"),
        _profile("time", dtype="time", example="01:02:11"),
        _profile("user"), _profile("status"),
        _profile("srcip", entity_type=EntityType.IP),
    ]
    fingerprint = _fingerprint(profiles, data_category=DataCategory.AUTHENTICATION_LOGS,
                               record_count=20)
    records = [
        LogRecord(line=index + 2, fields={"date": "2026-07-14", "time": f"01:{index:02d}:11"})
        for index in range(20)
    ]
    report = build_report("split.csv", fingerprint, records=records,
                          sigma_index=_sigma_index("T1110"))

    markdown = render_hypothesis_markdown(report, 0)

    assert "into @timestamp during ingest" in markdown


def test_the_filename_is_taken_from_the_behaviour():
    fingerprint = _fingerprint([_profile("host")], data_category=DataCategory.SYSTEM_LOGS)
    report = build_report("sample.csv", fingerprint, sigma_index=_sigma_index("T1543"))

    name = hypothesis_filename(report, 0)

    assert name.startswith("rejection-")
    assert name.endswith(".md")
    assert "service" in name or "persistence" in name or "creation" in name


def test_low_confidence_classification_is_flagged_in_the_report():
    fingerprint = _fingerprint(
        [_profile("host")], data_category=DataCategory.SYSTEM_LOGS, classification_confidence=0.15
    )

    markdown = render_markdown(build_report("sample.csv", fingerprint))

    assert "The data category itself is a guess" in markdown


def test_end_to_end_on_the_field_poor_fixture():
    """The Phase 2 Definition of Done, as an assertion."""
    from engine.profiling.data_classifier import classify
    from engine.profiling.field_profiler import build_fingerprint, profile_fields

    sample = parser.parse(APPLIANCE)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    fingerprint = build_fingerprint(
        profiles, classify(sample.field_names), record_count=sample.record_count
    )

    report = build_report(sample.path, fingerprint, records=sample.records,
                          sigma_index=_sigma_index("T1543", "T1070"))

    assert report.reports, "a field-poor sample must still produce reasoning"
    assert all(item.verdict == VERDICT_REJECTED for item in report.reports)
    # Reasoning, not just "no match": each rejection names the gap and a fix.
    for item in report.reports:
        assert item.failed_checks
        assert item.remediation
    assert "user identity" in report.onboarding_requirements
    assert "message" in render_markdown(report)
