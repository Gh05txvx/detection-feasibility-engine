"""Ingestion tests: format detection, flattening, and URL decoding."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.ingestion import parser
from engine.ingestion.schemas import SampleFormat

FIXTURES = Path(__file__).parent / "fixtures"
CLOUDFLARE = FIXTURES / "cloudflare_waf_firewall_events.csv"


def test_parses_csv_fixture():
    sample = parser.parse(CLOUDFLARE)

    assert sample.format is SampleFormat.CSV
    assert sample.delimiter == ","
    assert sample.record_count == 37
    assert sample.field_names[0] == "Datetime"
    assert "ClientRequestQuery" in sample.field_names
    assert not sample.problems


def test_limit_truncates_and_says_so():
    sample = parser.parse(CLOUDFLARE, limit=5)

    assert sample.record_count == 5
    assert sample.truncated is True


def test_query_string_is_url_decoded_and_original_kept():
    sample = parser.parse(CLOUDFLARE)
    record = next(r for r in sample.records if "8812" in str(r.fields.get("ClientRequestQuery", "")))

    # '+' is a space and %3D is '=' inside a query string.
    assert record.fields["ClientRequestQuery"] == "?id=8812 OR 1=1--"
    assert record.raw_fields["ClientRequestQuery"] == "?id=8812+OR+1%3D1--"


def test_untouched_values_do_not_land_in_raw_fields():
    sample = parser.parse(CLOUDFLARE)
    record = sample.records[0]

    assert "ClientIP" not in record.raw_fields
    assert record.fields["ClientIP"] == "203.0.113.24"


def test_plus_in_a_path_is_literal(tmp_path):
    path = tmp_path / "paths.csv"
    path.write_text("ClientRequestPath,ClientRequestQuery\n/a+b/c,?q=a+b\n", encoding="utf-8")

    record = parser.parse(path).records[0]

    # unquote_plus on a path would corrupt a legitimate '+' in a filename.
    assert record.fields["ClientRequestPath"] == "/a+b/c"
    assert record.fields["ClientRequestQuery"] == "?q=a b"


def test_parses_json_array(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(json.dumps([{"src": "10.0.0.1"}, {"src": "10.0.0.2"}]), encoding="utf-8")

    sample = parser.parse(path)

    assert sample.format is SampleFormat.JSON
    assert [record.fields["src"] for record in sample.records] == ["10.0.0.1", "10.0.0.2"]


def test_parses_jsonl(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"a": 1}\n{"a": 2}\n{"a": 3}\n', encoding="utf-8")

    sample = parser.parse(path)

    assert sample.format is SampleFormat.JSONL
    assert sample.record_count == 3


def test_jsonl_reports_a_bad_line_without_losing_the_rest(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"a": 1}\nnot json\n{"a": 3}\n', encoding="utf-8")

    sample = parser.parse(path)

    assert sample.record_count == 2
    assert any("line 2" in problem for problem in sample.problems)


def test_parses_elasticsearch_search_response(tmp_path):
    """The second input scenario: an export of a live index, not yet ECS."""
    path = tmp_path / "export.json"
    path.write_text(
        json.dumps({
            "took": 3,
            "hits": {
                "total": {"value": 2},
                "hits": [
                    {"_source": {"source": {"ip": "10.0.0.1"}, "event": {"action": "allow"}}},
                    {"_source": {"source": {"ip": "10.0.0.2"}, "event": {"action": "deny"}}},
                ],
            },
        }),
        encoding="utf-8",
    )

    sample = parser.parse(path)

    assert sample.format is SampleFormat.ELASTIC_RESPONSE
    assert sample.record_count == 2
    # Nested objects flatten to the dotted names ECS uses.
    assert sample.records[0].fields["source.ip"] == "10.0.0.1"
    assert sample.records[1].fields["event.action"] == "deny"


def test_scalar_lists_are_joined_not_dropped(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(json.dumps([{"tags": ["a", "b"], "nested": [{"x": 1}]}]), encoding="utf-8")

    record = parser.parse(path).records[0]

    assert record.fields["tags"] == "a, b"
    assert json.loads(record.fields["nested"]) == [{"x": 1}]


def test_duplicate_header_columns_are_kept_apart(tmp_path):
    """Two columns of the same name collapse in a dict, losing the first silently."""
    path = tmp_path / "dup.csv"
    path.write_text("srcip,srcip,dstip\n1.1.1.1,2.2.2.2,3.3.3.3\n", encoding="utf-8")

    sample = parser.parse(path)

    assert sample.field_names == ["srcip", "srcip__2", "dstip"]
    assert sample.records[0].fields["srcip"] == "1.1.1.1"
    assert sample.records[0].fields["srcip__2"] == "2.2.2.2"
    assert any("duplicate header" in problem for problem in sample.problems)


def test_blank_header_cells_get_a_name(tmp_path):
    path = tmp_path / "blank.csv"
    path.write_text("ip,,port\n1.1.1.1,x,80\n", encoding="utf-8")

    sample = parser.parse(path)

    assert sample.field_names == ["ip", "column_2", "port"]
    assert sample.records[0].fields["column_2"] == "x"


def test_plus_is_not_rewritten_in_a_value_that_was_never_encoded(tmp_path):
    """A database audit log's `query` column must not have SELECT a+b mangled."""
    path = tmp_path / "audit.csv"
    path.write_text("query,user\nSELECT a+b FROM t,budi\n", encoding="utf-8")

    record = parser.parse(path).records[0]

    assert record.fields["query"] == "SELECT a+b FROM t"
    assert "query" not in record.raw_fields


def test_w3c_query_column_decodes_without_a_percent_escape(tmp_path):
    """IIS logs the query with no leading '?' and often only '+' for spaces."""
    path = tmp_path / "iis.csv"
    path.write_text("cs-uri-query\nid=44+UNION+SELECT+1--\n", encoding="utf-8")

    record = parser.parse(path).records[0]

    assert record.fields["cs-uri-query"] == "id=44 UNION SELECT 1--"
    assert record.raw_fields["cs-uri-query"] == "id=44+UNION+SELECT+1--"


def test_plus_is_decoded_when_the_value_really_is_encoded(tmp_path):
    path = tmp_path / "web.csv"
    path.write_text("query\na%3D1+OR+2\n", encoding="utf-8")

    record = parser.parse(path).records[0]

    assert record.fields["query"] == "a=1 OR 2"


def test_zero_parseable_records_is_an_error_not_an_empty_sample(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{ not json at all", encoding="utf-8")

    with pytest.raises(parser.ParseError, match="no records could be parsed"):
        parser.parse(path)


def test_limit_below_one_is_refused():
    with pytest.raises(parser.ParseError, match="at least 1"):
        parser.parse(CLOUDFLARE, limit=0)


def test_missing_file_raises_parse_error(tmp_path):
    with pytest.raises(parser.ParseError):
        parser.parse(tmp_path / "nope.csv")


def test_empty_file_raises_parse_error(tmp_path):
    path = tmp_path / "empty.csv"
    path.write_text("   \n", encoding="utf-8")

    with pytest.raises(parser.ParseError):
        parser.parse(path)
