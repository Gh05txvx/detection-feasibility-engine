"""Profiling tests: entity recognition, field stats, classification, ECS gap."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.ingestion import parser
from engine.ingestion.schemas import LogRecord
from engine.profiling import ecs_gap
from engine.profiling.data_classifier import DataCategory, classify
from engine.profiling.ecs_gap import DataStreamProfile, IntegrationIndex, find_integration
from engine.profiling.entity_recognition import EntityType, detect_entity_type
from engine.profiling.field_profiler import (
    DATE_ORDER_AMBIGUOUS,
    DATE_ORDER_CONTRADICTORY,
    DATE_ORDER_DAY_FIRST,
    DATE_ORDER_MONTH_FIRST,
    EXAMPLE_VALUE_MAX,
    FieldProfile,
    build_examples,
    build_fingerprint,
    find_timestamp_source,
    parse_timestamp,
    profile_fields,
)

FIXTURES = Path(__file__).parent / "fixtures"
CLOUDFLARE = FIXTURES / "cloudflare_waf_firewall_events.csv"
FORTIGATE = FIXTURES / "fortinet_fortigate_traffic.csv"
WINDOWS = FIXTURES / "windows_security_logons.csv"
W3C = FIXTURES / "iis_w3c_access.csv"
SENTINEL = FIXTURES / "sentinel_slash_timestamps.csv"


# --------------------------------------------------------- entity recognition


@pytest.mark.parametrize(
    ("field_name", "values", "expected"),
    [
        ("ClientIP", ["203.0.113.24", "198.51.100.7"], EntityType.IP),
        ("srcip", ["2001:db8::1", "2001:db8::2"], EntityType.IP),
        ("sender", ["a@example.com", "b@example.org"], EntityType.EMAIL),
        ("referer", ["https://example.com/a", "http://example.org"], EntityType.URL),
        ("sha256", ["a" * 64, "b" * 64], EntityType.HASH),
        ("srcport", ["443", "8080"], EntityType.PORT),
        ("TargetUserName", ["rahmawati", "pratama"], EntityType.USER),
        ("ImagePath", ["C:\\Windows\\System32\\cmd.exe"], EntityType.PROCESS_NAME),
        ("dns_name", ["mail.example.com", "api.example.co.id"], EntityType.DOMAIN),
    ],
)
def test_detects_entity_types(field_name, values, expected):
    assert detect_entity_type(field_name, values) is expected


def test_port_needs_a_name_hint():
    """Status codes are small integers too; only the name says 'port'."""
    assert detect_entity_type("EdgeResponseStatus", ["403", "200"]) is None
    assert detect_entity_type("dstport", ["403", "200"]) is EntityType.PORT


def test_user_words_inside_another_noun_are_not_users():
    """LogonProcessName contains 'logon' but names a process, not an account."""
    assert detect_entity_type("LogonProcessName", ["NtLmSsp", "User32"]) is None
    assert detect_entity_type("AuthenticationPackageName", ["NTLM", "Negotiate"]) is None


def test_url_path_is_not_a_file_path():
    """'/products' in a request field is a URL path; calling it file.path misleads."""
    assert detect_entity_type("ClientRequestPath", ["/products/1", "/search/x"]) is None
    assert detect_entity_type("file_path", ["/etc/passwd/x", "/var/log/y"]) is EntityType.FILE_PATH


def test_mixed_values_below_threshold_stay_unlabelled():
    assert detect_entity_type("mixed", ["10.0.0.1", "banana", "carrot", "durian"]) is None


# ------------------------------------------------------------ field profiling


def test_profiles_the_cloudflare_fixture():
    sample = parser.parse(CLOUDFLARE)
    profiles = {p.field_name: p for p in profile_fields(sample.records, field_names=sample.field_names)}

    assert profiles["ClientIP"].entity_type is EntityType.IP
    assert profiles["Datetime"].dtype == "timestamp"
    assert profiles["EdgeResponseStatus"].dtype == "integer"
    assert profiles["ClientRequestHost"].cardinality == 2
    # RuleID is empty on most rows, and that emptiness is the signal.
    assert profiles["RuleID"].null_rate > 0.5


def test_field_order_follows_the_source_file():
    sample = parser.parse(CLOUDFLARE)
    profiles = profile_fields(sample.records, field_names=sample.field_names)

    assert [p.field_name for p in profiles] == sample.field_names


def test_dash_placeholder_counts_as_empty(tmp_path):
    """Windows exports write '-' for absent values; counting it hides the real IPs."""
    path = tmp_path / "logons.csv"
    path.write_text("IpAddress\n10.0.0.1\n-\n10.0.0.2\n-\n", encoding="utf-8")
    sample = parser.parse(path)

    profile = profile_fields(sample.records)[0]

    assert profile.null_rate == 0.5
    assert profile.cardinality == 2
    assert profile.entity_type is EntityType.IP


def test_top_values_report_the_distribution():
    sample = parser.parse(CLOUDFLARE)
    profiles = {p.field_name: p for p in profile_fields(sample.records)}

    top_action, count = profiles["Action"].top_values[0]
    assert top_action == "allow"
    assert count > 1


# ------------------------------------------------------------ event time


def test_a_full_timestamp_column_is_the_event_time():
    profiles = [FieldProfile(field_name="Datetime", dtype="timestamp", cardinality=37,
                             null_rate=0.0, example="2026-03-11T09:02:05Z")]

    source = find_timestamp_source(profiles)

    assert source.field_name == "Datetime"
    assert source.is_split is False
    assert source.granularity == "second"


def test_a_date_column_plus_a_time_column_is_one_event_time():
    """W3C/IIS specifies date and time as separate fields; so does FortiGate."""
    profiles = [
        FieldProfile(field_name="date", dtype="date", cardinality=1, null_rate=0.0,
                     example="2026-07-14"),
        FieldProfile(field_name="time", dtype="time", cardinality=20, null_rate=0.0,
                     example="01:02:11"),
    ]

    source = find_timestamp_source(profiles)

    assert source.is_split is True
    assert (source.date_field, source.time_field) == ("date", "time")
    assert source.granularity == "second"
    assert source.resolve({"date": "2026-07-14", "time": "01:02:11"}).hour == 1


def test_a_lone_date_or_a_lone_time_is_not_an_event_time():
    """Neither can place an event on a timeline, and midnight is not an answer."""
    only_date = [FieldProfile(field_name="date", dtype="date", cardinality=1, null_rate=0.0)]
    only_time = [FieldProfile(field_name="time", dtype="time", cardinality=9, null_rate=0.0)]

    assert find_timestamp_source(only_date) is None
    assert find_timestamp_source(only_time) is None


def test_a_bare_date_does_not_parse_to_midnight():
    assert parse_timestamp("2026-04-02") is None
    assert parse_timestamp("2026-04-02", allow_date_only=True).hour == 0
    assert parse_timestamp("2026-04-02 08:14:21").hour == 8


def test_date_and_time_columns_get_their_own_dtypes():
    sample = parser.parse(W3C)
    profiles = {p.field_name: p for p in profile_fields(sample.records, field_names=sample.field_names)}

    assert profiles["date"].dtype == "date"
    assert profiles["time"].dtype == "time"


def test_w3c_sample_resolves_its_event_time():
    sample = parser.parse(W3C)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    fingerprint = build_fingerprint(profiles, classify(sample.field_names),
                                    record_count=sample.record_count)

    source = fingerprint.timestamp_source()

    assert source is not None and source.is_split
    moments = [source.resolve(record.fields) for record in sample.records]
    assert all(moment is not None for moment in moments)
    span = (max(moments) - min(moments)).total_seconds()
    assert span == 8145  # 01:02:11 to 03:17:56, the range the fixture covers


# ------------------------------------------------------------ event examples


def test_examples_lead_with_the_fields_the_verdict_turned_on():
    sample = parser.parse(CLOUDFLARE)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    source = find_timestamp_source(profiles)

    examples = build_examples(
        sample.records, source=source, key_fields=["ClientRequestPath", "Action"], limit=2
    )

    assert len(examples) == 2
    assert [name for name, _ in examples[0].key_fields] == ["ClientRequestPath", "Action"]
    assert examples[0].timestamp is not None
    assert examples[0].raw_timestamp == sample.records[0].fields["Datetime"]
    # Event time has its own column, so it is not repeated among the others.
    assert "Datetime" not in [name for name, _ in examples[0].other_fields]
    # Blank columns are dropped: a row of dashes hides the values that matter.
    assert all(value.strip() for _, value in examples[0].other_fields)


def test_a_long_value_is_shortened_rather_than_dropped():
    """A payload in a URL is the evidence; truncating beats omitting."""
    record = LogRecord(line=4, fields={"url": "/a?q=" + "x" * 500})

    example = build_examples([record], key_fields=["url"])[0]

    value = dict(example.key_fields)["url"]
    assert len(value) == EXAMPLE_VALUE_MAX
    assert value.startswith("/a?q=xxx")
    assert value.endswith("…")


# --------------------------------------------- slash-separated date ordering


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        # One day above 12 anywhere in the column settles the whole column.
        (["16/07/2026 20:26:12.030", "07/06/2026 08:00:00"], DATE_ORDER_DAY_FIRST),
        (["07/16/2026 20:26:12.030", "06/07/2026 08:00:00"], DATE_ORDER_MONTH_FIRST),
        # Every value fits both readings, so the column proves nothing.
        (["07/06/2026 08:00:00", "01/02/2026 09:00:00"], DATE_ORDER_AMBIGUOUS),
        # Both positions exceed 12 somewhere: no single order reads the column.
        (["16/07/2026 20:26:12", "07/16/2026 20:26:12"], DATE_ORDER_CONTRADICTORY),
        # Not slash-dated at all.
        (["2026-07-16T20:26:12Z"], None),
        ([], None),
    ],
)
def test_date_order_is_decided_across_the_column(values, expected):
    profiles = profile_fields([_record({"TimeGenerated": value}) for value in values]) if values else []
    order = profiles[0].date_order if profiles else None
    assert order == expected


def test_an_ambiguous_date_order_is_refused_rather_than_guessed():
    """A wrong guess does not fail loudly; it moves events to another date."""
    assert parse_timestamp("07/06/2026 08:00:00") is None
    assert parse_timestamp("07/06/2026 08:00:00", date_order=DATE_ORDER_AMBIGUOUS) is None
    assert parse_timestamp("07/06/2026 08:00:00", date_order=DATE_ORDER_CONTRADICTORY) is None

    day_first = parse_timestamp("07/06/2026 08:00:00", date_order=DATE_ORDER_DAY_FIRST)
    month_first = parse_timestamp("07/06/2026 08:00:00", date_order=DATE_ORDER_MONTH_FIRST)
    assert (day_first.month, day_first.day) == (6, 7)
    assert (month_first.month, month_first.day) == (7, 6)


def test_the_sentinel_export_shape_resolves_its_event_time():
    """16/07/2026 20:26:12.030 under `TimeGenerated [Local Time]`, as exported."""
    sample = parser.parse(SENTINEL)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    fingerprint = build_fingerprint(profiles, classify(sample.field_names),
                                    record_count=sample.record_count)

    source = fingerprint.timestamp_source()

    assert source.field_name == "TimeGenerated [Local Time]"
    assert source.date_order == DATE_ORDER_DAY_FIRST  # 16/07 and 17/07 settle it
    assert source.is_readable
    assert source.granularity == "second"

    moments = [source.resolve(record.fields) for record in sample.records]
    assert all(moment is not None for moment in moments)
    assert (min(moments).month, min(moments).day) == (7, 16)
    # 16 Jul 20:26:12.030 to 17 Jul 18:09:27.842
    assert round((max(moments) - min(moments)).total_seconds(), 3) == 78195.812


def test_a_local_time_column_asks_for_its_offset():
    """The name says local, the value carries no offset: @timestamp would be off."""
    sample = parser.parse(SENTINEL)
    profiles = profile_fields(sample.records, field_names=sample.field_names)

    source = find_timestamp_source(profiles)

    assert source.declares_local_time
    assert any("UTC offset" in ask for ask in source.format_requirements)


def test_an_unreadable_timestamp_is_not_reported_as_a_missing_one():
    """The field is there; the ask is to confirm a format, not to add a column."""
    profiles = [FieldProfile(field_name="TimeGenerated", dtype="timestamp", cardinality=2,
                             null_rate=0.0, example="07/06/2026 08:00:00",
                             date_order=DATE_ORDER_AMBIGUOUS)]

    source = find_timestamp_source(profiles)

    assert source is not None                      # not "no timestamp"
    assert source.is_readable is False
    assert source.resolve({"TimeGenerated": "07/06/2026 08:00:00"}) is None
    assert any("day-first or month-first" in ask for ask in source.ingest_requirements)


def _record(fields: dict[str, str]) -> LogRecord:
    return LogRecord(line=1, fields=fields)


# ---------------------------------------------------------- data classifier


def test_classifies_cloudflare_firewall_events():
    sample = parser.parse(CLOUDFLARE)
    result = classify(sample.field_names)

    assert (result.inferred_category, result.inferred_product, result.inferred_service) == (
        "webserver",
        "cloudflare",
        "firewall_events",
    )
    assert result.data_category is DataCategory.APPLICATION_LOGS
    assert result.evidence


def test_classifies_fortigate_and_windows():
    fortigate = classify(parser.parse(FORTIGATE).field_names)
    assert fortigate.inferred_product == "fortinet_fortigate"
    assert fortigate.data_category is DataCategory.NETWORK_LOGS

    windows = classify(parser.parse(WINDOWS).field_names)
    assert (windows.inferred_product, windows.inferred_service) == ("windows", "security")
    assert windows.data_category is DataCategory.AUTHENTICATION_LOGS


def test_classifies_the_cloudflare_http_requests_shape():
    """What actually reaches Sentinel: HTTP requests with WAF attack scores."""
    fixture = FIXTURES / "cloudflare_http_requests_attackscore.csv"
    result = classify(parser.parse(fixture).field_names)

    assert (result.inferred_product, result.inferred_service) == ("cloudflare", "http_requests")
    assert result.confidence >= 0.9


def test_unknown_source_gets_no_invented_logsource():
    result = classify(["colA", "colB", "colC"])

    assert result.inferred_category is None
    assert result.inferred_product is None
    assert result.evidence  # says why, rather than failing silently


def test_dotted_ecs_names_satisfy_short_signature_fields():
    result = classify(["event.srcip", "event.dstip", "network.bytes"])

    assert result.inferred_product == "fortinet_fortigate"


# ----------------------------------------------------------------- ecs gap


def _index(*streams: DataStreamProfile) -> IntegrationIndex:
    return IntegrationIndex(
        corpus_path="test",
        fingerprint="test",
        pipeline_files=0,
        data_streams=list(streams),
        ecs_fields=["source.ip", "destination.ip", "url.path"],
    )


def test_focused_data_stream_beats_a_verbose_one():
    """Regression: FortiProxy declares 424 fields to FortiGate's 272 and won on
    raw overlap alone, which is the wrong integration to hand an implementer."""
    sample_fields = ["srcip", "dstip", "srcport", "dstport", "action", "policyid"]
    verbose = DataStreamProfile(
        package="vendor_bigger",
        data_stream="log",
        source_fields=sorted(set(sample_fields) | {f"filler{n}" for n in range(400)}),
        ecs_mappings={},
    )
    focused = DataStreamProfile(
        package="vendor_right",
        data_stream="log",
        source_fields=sorted(set(sample_fields[:5]) | {f"filler{n}" for n in range(15)}),
        ecs_mappings={"srcip": "source.ip"},
    )

    match = find_integration(_index(verbose, focused), sample_fields)

    assert match is not None
    assert match.package == "vendor_right"


def test_product_hint_breaks_a_near_tie():
    sample_fields = ["srcip", "dstip", "srcport", "dstport"]
    common = sorted(set(sample_fields) | {f"filler{n}" for n in range(20)})
    proxy = DataStreamProfile(package="vendor_proxy", data_stream="log", source_fields=common)
    gate = DataStreamProfile(package="vendor_gate", data_stream="log", source_fields=common)

    match = find_integration(_index(proxy, gate), sample_fields, product_hint="vendor_gate")

    assert match is not None
    assert match.package == "vendor_gate"


def test_integration_mappings_resolve_by_short_name():
    """Pipelines state `fortinet.firewall.srcip`; the sample column is `srcip`."""
    stream = DataStreamProfile(
        package="vendor",
        data_stream="log",
        source_fields=["srcip", "dstip", "action", "fortinet.firewall.srcip"],
        ecs_mappings={"fortinet.firewall.srcip": "source.ip"},
    )
    # Three fields minimum, or the data stream is not considered a match at all.
    profiles = [
        FieldProfile(field_name="srcip", dtype="string", cardinality=3, null_rate=0.0,
                     entity_type=EntityType.IP, is_ecs_compliant=False),
        FieldProfile(field_name="dstip", dtype="string", cardinality=3, null_rate=0.0,
                     entity_type=EntityType.IP, is_ecs_compliant=False),
        FieldProfile(field_name="action", dtype="string", cardinality=2, null_rate=0.0),
    ]

    report = ecs_gap.analyse(profiles, _index(stream))

    assert report.integration is not None
    assert report.mapped_fields == {"srcip": "source.ip"}
    assert profiles[0].suggested_ecs_field == "source.ip"


def test_heuristics_apply_when_no_integration_matches():
    profiles = [
        FieldProfile(field_name="Computer", dtype="string", cardinality=4, null_rate=0.0,
                     entity_type=EntityType.DOMAIN),
        FieldProfile(field_name="TargetUserName", dtype="string", cardinality=9, null_rate=0.0,
                     entity_type=EntityType.USER),
        FieldProfile(field_name="TimeCreated", dtype="timestamp", cardinality=19, null_rate=0.0),
    ]

    report = ecs_gap.analyse(profiles, _index())

    # An FQDN in a machine field is a host, not a DNS question.
    assert report.suggested_fields["Computer"] == "host.name"
    # 'Target' is the account acted on, not a network peer.
    assert report.suggested_fields["TargetUserName"] == "user.name"
    assert report.suggested_fields["TimeCreated"] == "@timestamp"


def test_already_ecs_fields_are_left_alone():
    profiles = [
        FieldProfile(field_name="source.ip", dtype="string", cardinality=3, null_rate=0.0,
                     entity_type=EntityType.IP),
    ]

    report = ecs_gap.analyse(profiles, _index())

    assert report.compliant_fields == ["source.ip"]
    assert profiles[0].is_ecs_compliant is True
    assert profiles[0].suggested_ecs_field is None


def test_split_timestamp_is_reported_as_an_ingest_requirement():
    profiles = [
        FieldProfile(field_name="date", dtype="date", cardinality=1, null_rate=0.0),
        FieldProfile(field_name="time", dtype="time", cardinality=20, null_rate=0.0),
        FieldProfile(field_name="c-ip", dtype="string", cardinality=6, null_rate=0.0),
    ]

    report = ecs_gap.analyse(profiles, _index())

    assert any("split across 'date' and 'time'" in note for note in report.notes)
    assert profiles[0].suggested_ecs_field == "@timestamp"
    assert profiles[1].suggested_ecs_field == "@timestamp"


def test_w3c_names_are_mapped_by_specification_rather_than_guessed():
    """`iis / access` groks a whole request line, so it exposes almost no source
    names and no IIS export resolves to it. W3C Extended has a closed field list,
    which can be mapped outright."""
    sample = parser.parse(W3C)
    profiles = profile_fields(sample.records, field_names=sample.field_names)

    report = ecs_gap.analyse(profiles, _index())

    # `c-` is the client by definition. Entity recognition sees only an IP whose
    # name carries no direction word, and would settle for related.ip.
    assert report.suggested_fields["c-ip"] == "source.ip"
    assert report.suggested_fields["cs-method"] == "http.request.method"
    assert report.suggested_fields["cs-uri-stem"] == "url.path"
    assert report.suggested_fields["sc-status"] == "http.response.status_code"
    assert report.suggested_fields["cs-user-agent"] == "user_agent.original"
    # Milliseconds against ECS's nanosecond event.duration: a rename alone cannot
    # convert the unit, so no mapping is offered.
    assert "time-taken" in report.unmapped_fields


def test_no_ecs_field_is_invented_for_a_port_or_hash_that_names_neither():
    profiles = [
        FieldProfile(field_name="IpPort", dtype="integer", cardinality=9, null_rate=0.0,
                     entity_type=EntityType.PORT),
        FieldProfile(field_name="Checksum", dtype="string", cardinality=9, null_rate=0.0,
                     entity_type=EntityType.HASH),
        FieldProfile(field_name="FileSha1", dtype="string", cardinality=9, null_rate=0.0,
                     entity_type=EntityType.HASH),
    ]

    report = ecs_gap.analyse(profiles, _index())

    # ECS puts ports on an end of the connection and names the hash algorithm in
    # the field; neither has a generic field to fall back on.
    assert "IpPort" in report.unmapped_fields
    assert "Checksum" in report.unmapped_fields
    assert report.suggested_fields["FileSha1"] == "file.hash.sha1"


def test_a_suggestion_naming_a_field_the_corpus_never_heard_of_is_dropped():
    """A heuristic that reads as authoritative but points at a field no index
    holds is worse than no suggestion: it reaches the runbook query and the
    generated ingest pipeline."""
    harvested = IntegrationIndex(
        corpus_path="test", fingerprint="test", pipeline_files=12,
        ecs_fields=["source.ip", "user.name"],
    )
    profiles = [
        FieldProfile(field_name="devname", dtype="string", cardinality=2, null_rate=0.0),
        FieldProfile(field_name="srcip", dtype="string", cardinality=4, null_rate=0.0,
                     entity_type=EntityType.IP),
    ]

    report = ecs_gap.analyse(profiles, harvested)

    assert report.suggested_fields["srcip"] == "source.ip"
    assert "devname" in report.unmapped_fields          # observer.name is not in this vocabulary
    assert profiles[0].suggested_ecs_field is None
    assert any("devname -> observer.name" in note for note in report.notes)


def test_the_vocabulary_check_needs_a_vocabulary_that_was_actually_harvested():
    """An index built from no pipeline files holds whatever list it was handed,
    which is not evidence about what ECS contains."""
    profiles = [FieldProfile(field_name="devname", dtype="string", cardinality=2, null_rate=0.0)]

    report = ecs_gap.analyse(profiles, _index())

    assert report.suggested_fields["devname"] == "observer.name"


def test_index_cache_key_includes_the_indexer_version():
    """Without this, a cache written by an older build is reused forever: the
    corpus files have not changed, so a count-and-mtime key still matches."""
    key = ecs_gap._corpus_fingerprint(Path("does-not-exist"))

    assert key.startswith(f"v{ecs_gap.INDEX_SCHEMA_VERSION}:")


def test_missing_corpus_is_reported_not_hidden():
    profiles = [FieldProfile(field_name="srcip", dtype="string", cardinality=1, null_rate=0.0)]

    report = ecs_gap.analyse(profiles, None)

    assert report.integration is None
    assert any("not cloned" in note for note in report.notes)
