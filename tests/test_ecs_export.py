"""ECS export tests: the two objects a normalized index gets deployed from."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.ingestion import parser
from engine.profiling import ecs_export, ecs_gap
from engine.profiling.data_classifier import Classification, classify
from engine.profiling.ecs_export import MappingOrigin
from engine.profiling.ecs_gap import EcsGapReport
from engine.profiling.field_profiler import (
    DATE_ORDER_AMBIGUOUS,
    NULL_PLACEHOLDERS,
    FieldProfile,
    build_fingerprint,
    profile_fields,
)

FIXTURES = Path(__file__).parent / "fixtures"
CLOUDFLARE = FIXTURES / "cloudflare_waf_firewall_events.csv"
FORTIGATE = FIXTURES / "fortinet_fortigate_traffic.csv"
WINDOWS = FIXTURES / "windows_security_logons.csv"
W3C = FIXTURES / "iis_w3c_access.csv"
SENTINEL = FIXTURES / "sentinel_slash_timestamps.csv"
APPLIANCE = FIXTURES / "minimal_appliance_syslog.csv"

ALL_FIXTURES = [CLOUDFLARE, FORTIGATE, WINDOWS, W3C, SENTINEL, APPLIANCE]


def export_for(path: Path) -> ecs_export.EcsExport:
    """One sample taken the whole way to its deployable form, corpus-free."""
    sample = parser.parse(path)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    classification = classify(sample.field_names)
    gap = ecs_gap.analyse(profiles, None, product_hint=classification.inferred_product)
    fingerprint = build_fingerprint(profiles, classification, record_count=sample.record_count)
    return ecs_export.build(fingerprint, gap, sample_name=path.name)


def export_from(profiles: list[FieldProfile], **classification) -> ecs_export.EcsExport:
    """Export hand-built profiles, with no gap analysis to overwrite them."""
    fingerprint = build_fingerprint(profiles, Classification(**classification))
    return ecs_export.build(fingerprint, EcsGapReport(), sample_name="sample.csv")


def options(export: ecs_export.EcsExport, processor: str) -> list[dict]:
    return [
        entry[processor]
        for entry in export.ingest_pipeline["processors"]
        if processor in entry
    ]


def renames(export: ecs_export.EcsExport) -> dict[str, str]:
    return {entry["field"]: entry["target_field"] for entry in options(export, "rename")}


def mapped_type(export: ecs_export.EcsExport, field: str) -> str | None:
    """The type the index template gives one dotted field."""
    node = export.index_template["template"]["mappings"]["properties"]
    parts = field.split(".")
    for part in parts[:-1]:
        node = node[part]["properties"]
    return node[parts[-1]].get("type")


# ------------------------------------------------------------ what gets moved


def test_vendor_fields_are_renamed_to_the_ecs_field_the_gap_analysis_resolved():
    moves = renames(export_for(FORTIGATE))

    assert moves["srcip"] == "source.ip"
    assert moves["srcport"] == "source.port"
    assert moves["dstip"] == "destination.ip"
    assert moves["level"] == "log.level"


def test_a_field_with_no_ecs_equivalent_moves_under_the_vendor_namespace():
    """Left at the root, a later ECS release could claim the name underneath it."""
    export = export_for(FORTIGATE)

    assert export.namespace == "fortinet_fortigate"
    assert renames(export)["srcintf"] == "fortinet_fortigate.srcintf"
    assert renames(export)["appcat"] == "fortinet_fortigate.appcat"


def test_camel_and_hyphen_names_are_written_the_way_ecs_writes_names():
    assert renames(export_for(CLOUDFLARE))["ClientRequestPath"] == "cloudflare.client_request_path"
    # `time-taken` is milliseconds where ECS `event.duration` is nanoseconds, so
    # it is deliberately left unmapped rather than silently rescaled.
    assert renames(export_for(W3C))["time-taken"] == "webserver.time_taken"


@pytest.mark.parametrize("path", ALL_FIXTURES, ids=lambda path: path.stem)
def test_every_detected_field_is_accounted_for(path):
    """The point of the download: nothing profiled is quietly left out of it."""
    sample = parser.parse(path)
    export = export_for(path)

    assert [mapping.source_field for mapping in export.mappings] == sample.field_names
    assert export.to_ecs + export.to_namespace == len(sample.field_names)


# --------------------------------------------------------------- event time


def test_a_split_date_and_time_are_joined_before_they_are_parsed():
    """W3C specifies event time this way and FortiGate writes it this way."""
    export = export_for(FORTIGATE)

    join = options(export, "set")[-1]
    assert join["field"] == ecs_export.TMP_EVENT_TIME
    assert join["value"] == "{{{date}}} {{{time}}}"
    assert join["if"] == "ctx['date'] != null && ctx['time'] != null"

    parsed = options(export, "date")[0]
    assert parsed["field"] == ecs_export.TMP_EVENT_TIME
    assert parsed["target_field"] == "@timestamp"
    assert parsed["formats"] == ["yyyy-MM-dd H:mm:ss"]
    assert {"field": ecs_export.TMP_ROOT, "ignore_missing": True} in options(export, "remove")


def test_a_separator_dated_column_is_read_in_the_order_the_column_settled():
    export = export_for(SENTINEL)

    assert options(export, "date")[0]["formats"] == ["d/M/yyyy H:mm:ss.SSS", "d/M/yyyy H:mm:ss"]


def test_an_unsettled_date_order_writes_no_date_processor():
    """A pattern picked at random moves every event by months, and does it quietly."""
    export = export_from(
        [
            FieldProfile(
                field_name="TimeGenerated",
                dtype="timestamp",
                cardinality=2,
                null_rate=0.0,
                example="07/06/2026 08:00:00",
                date_order=DATE_ORDER_AMBIGUOUS,
            )
        ]
    )

    assert options(export, "date") == []
    assert any("day-first or month-first" in line for line in export.review)


def test_a_sample_with_no_event_time_says_so_rather_than_reaching_for_ingest_time():
    export = export_from(
        [FieldProfile(field_name="msg", dtype="string", cardinality=2, null_rate=0.0)]
    )

    assert options(export, "date") == []
    assert any("No event-time column" in line for line in export.review)
    assert not any("_ingest.timestamp" in json.dumps(entry) for entry in export.ingest_pipeline["processors"])


def test_a_local_time_column_is_flagged_rather_than_quietly_read_as_utc():
    export = export_for(SENTINEL)

    parsed = options(export, "date")[0]
    assert parsed["timezone"] == "UTC"
    assert "IANA zone" in parsed["description"]
    assert any("wrong by that offset" in line for line in export.review)


def test_the_original_of_a_parsed_timestamp_is_kept_as_text():
    """If the parse turns out to be off by a timezone, this is what fixes it."""
    export = export_for(CLOUDFLARE)

    assert options(export, "date")[0]["field"] == "Datetime"
    assert renames(export)["Datetime"] == "cloudflare.datetime"
    assert mapped_type(export, "cloudflare.datetime") == "keyword"


# ------------------------------------------------------- collisions and types


def test_related_ip_is_appended_so_a_second_address_cannot_overwrite_the_first():
    export = export_for(WINDOWS)

    appended = [entry for entry in options(export, "append") if entry["field"] == "related.ip"]
    assert appended == [
        {
            "field": "related.ip",
            "value": "{{{IpAddress}}}",
            "allow_duplicates": False,
            "if": "ctx['IpAddress'] != null",
        }
    ]
    # And the column it came from is still attributable.
    assert renames(export)["IpAddress"] == "windows.ip_address"


def test_two_fields_that_resolve_to_one_ecs_target_do_not_overwrite_each_other():
    export = export_from(
        [
            FieldProfile(field_name="srcip", dtype="string", cardinality=2, null_rate=0.0,
                         suggested_ecs_field="source.ip", example="10.0.0.1"),
            FieldProfile(field_name="src_address", dtype="string", cardinality=2, null_rate=0.0,
                         suggested_ecs_field="source.ip", example="10.0.0.2"),
        ]
    )

    moves = renames(export)
    assert moves["srcip"] == "source.ip"
    assert moves["src_address"] == "sample.src_address"
    assert any("source.ip" in conflict for conflict in export.conflicts)
    assert export.conflicts[0] in export.review


def test_an_identifier_with_leading_zeros_is_not_indexed_as_a_number():
    """FortiGate's logid is 0000000013; as a long the value a rule matches is gone."""
    export = export_for(FORTIGATE)

    assert mapped_type(export, "fortinet_fortigate.logid") == "keyword"
    assert mapped_type(export, "fortinet_fortigate.sessionid") == "long"


def test_an_ecs_field_set_is_not_indexed_as_if_it_were_a_field():
    """`host` passes the ECS check but is a field set: a value under it collides."""
    assert renames(export_for(APPLIANCE))["host"] == "host.name"

    export = export_for(FORTIGATE)
    service = next(m for m in export.mappings if m.source_field == "service")
    assert service.origin is MappingOrigin.CUSTOM
    assert service.target_field == "fortinet_fortigate.service"
    assert "field set" in (service.note or "")


def test_a_field_already_written_in_ecs_is_left_alone():
    export = export_for(APPLIANCE)

    assert "message" not in renames(export)
    assert mapped_type(export, "message") == "match_only_text"


# ------------------------------------------------------------------ the bodies


def test_blank_values_are_dropped_before_a_typed_field_can_see_one():
    """`source.ip` mapped as `ip` rejects "", and W3C writes `-` for every gap."""
    export = export_for(W3C)

    script = options(export, "script")[0]
    assert script["params"]["blanks"] == sorted(NULL_PLACEHOLDERS)
    assert script["params"]["fields"] == [m.source_field for m in export.mappings]


def test_the_index_template_types_what_the_pipeline_produces():
    export = export_for(FORTIGATE)

    assert mapped_type(export, "@timestamp") == "date"
    assert mapped_type(export, "source.ip") == "ip"
    assert mapped_type(export, "source.port") == "long"
    assert mapped_type(export, "fortinet_fortigate.srcintf") == "keyword"
    assert {"field": "source.port", "type": "long", "ignore_missing": True} in options(export, "convert")


def test_the_template_installs_the_pipeline_it_ships_with():
    export = export_for(CLOUDFLARE)
    template = export.index_template

    assert export.pipeline_id == "logs-cloudflare.firewall_events-ecs-normalization"
    assert export.template_id == "logs-cloudflare.firewall_events"
    assert template["index_patterns"] == ["logs-cloudflare.firewall_events-*"]
    assert template["data_stream"] == {}
    assert template["priority"] > 100  # Elastic's own `logs` template sits at 100
    assert template["template"]["settings"]["index.default_pipeline"] == export.pipeline_id


def test_an_unclassified_sample_still_gets_a_name_from_its_file():
    export = export_from(
        [FieldProfile(field_name="msg", dtype="string", cardinality=2, null_rate=0.0)]
    )

    assert export.dataset == "sample.log"
    assert export.namespace == "sample"


def test_both_bodies_are_json_and_neither_claims_to_have_been_deployed():
    export = export_for(CLOUDFLARE)

    assert json.loads(export.pipeline_json) == export.ingest_pipeline
    assert json.loads(export.template_json) == export.index_template
    for body in (export.ingest_pipeline, export.index_template):
        assert "was applied to Elastic" in body["_meta"]["not_deployed"]
    assert export.ingest_pipeline["_meta"]["sample"] == CLOUDFLARE.name
    assert export.ingest_pipeline["_meta"]["field_mapping"]["ClientIP"] == "source.ip"


def test_both_bodies_write_to_disk_under_the_id_they_deploy_as(tmp_path):
    """The CLI is where the real-sample runs happen, so it needs the files too."""
    export = export_for(FORTIGATE)

    written = ecs_export.write(export, tmp_path / "out")

    assert [path.name for path in written] == [
        "logs-fortinet_fortigate.firewall-ecs-normalization.json",
        "logs-fortinet_fortigate.firewall-index-template.json",
    ]
    assert json.loads(written[0].read_text(encoding="utf-8")) == export.ingest_pipeline
    # Re-running the same source overwrites rather than accumulating.
    assert ecs_export.write(export, tmp_path / "out") == written
    assert len(list((tmp_path / "out").iterdir())) == 2


def test_a_failed_document_is_tagged_rather_than_dropped():
    export = export_for(CLOUDFLARE)

    failure = json.dumps(export.ingest_pipeline["on_failure"])
    assert ecs_export.FAILURE_TAG in failure
    assert "_ingest.on_failure_message" in failure
