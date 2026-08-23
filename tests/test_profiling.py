"""Profiling tests: entity recognition, field stats, classification, ECS gap."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.ingestion import parser
from engine.profiling import ecs_gap
from engine.profiling.data_classifier import DataCategory, classify
from engine.profiling.ecs_gap import DataStreamProfile, IntegrationIndex, find_integration
from engine.profiling.entity_recognition import EntityType, detect_entity_type
from engine.profiling.field_profiler import FieldProfile, profile_fields

FIXTURES = Path(__file__).parent / "fixtures"
CLOUDFLARE = FIXTURES / "cloudflare_waf_firewall_events.csv"
FORTIGATE = FIXTURES / "fortinet_fortigate_traffic.csv"
WINDOWS = FIXTURES / "windows_security_logons.csv"


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


def test_missing_corpus_is_reported_not_hidden():
    profiles = [FieldProfile(field_name="srcip", dtype="string", cardinality=1, null_rate=0.0)]

    report = ecs_gap.analyse(profiles, None)

    assert report.integration is None
    assert any("not cloned" in note for note in report.notes)
