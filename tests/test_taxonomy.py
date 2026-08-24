"""Internal taxonomy: matching against a fingerprint, and the authoring workflow."""

from __future__ import annotations

import json

import pytest

from engine.matching import taxonomy_matcher
from engine.matching.candidate import MatchSource
from engine.profiling.data_classifier import DataCategory
from engine.profiling.field_profiler import FieldProfile, LogFingerprint
from engine.storage import db, taxonomy_store
from engine.storage.taxonomy_store import TaxonomyEntry
from scripts import taxonomy as taxonomy_cli


def _fingerprint(**overrides) -> LogFingerprint:
    defaults = dict(
        profiles=[
            FieldProfile(field_name="ClientIP", dtype="string", cardinality=8, null_rate=0.0,
                         suggested_ecs_field="source.ip"),
            FieldProfile(field_name="ClientRequestQuery", dtype="string", cardinality=11, null_rate=0.7,
                         suggested_ecs_field="url.query"),
            FieldProfile(field_name="Action", dtype="string", cardinality=4, null_rate=0.0),
        ],
        inferred_category="webserver",
        inferred_product="cloudflare",
        inferred_service="firewall_events",
        data_category=DataCategory.APPLICATION_LOGS,
        record_count=37,
    )
    defaults.update(overrides)
    return LogFingerprint(**defaults)


def _entry(**overrides) -> TaxonomyEntry:
    defaults = dict(
        slug="cloudflare-test",
        name="Cloudflare test entry",
        logsource_category="webserver",
        logsource_product="cloudflare",
        logsource_service="firewall_events",
        data_category="application_logs",
        required_fields=["ClientIP", "Action"],
        mitre_techniques=["T1190"],
        confidence=0.8,
    )
    defaults.update(overrides)
    return TaxonomyEntry(**defaults)


# ------------------------------------------------------------------- matching


def test_matches_an_entry_for_this_log_source():
    candidates = taxonomy_matcher.match(_fingerprint(), [_entry()])

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.source is MatchSource.INTERNAL_TAXONOMY
    assert candidate.rule_ref == "internal:cloudflare-test"
    assert candidate.matched_fields == {"ClientIP": "ClientIP", "Action": "Action"}
    assert candidate.mitre_techniques == ["T1190"]


def test_entry_for_another_product_is_excluded():
    assert taxonomy_matcher.match(_fingerprint(), [_entry(logsource_product="fortinet")]) == []


def test_contradicting_data_category_excludes_the_entry():
    assert taxonomy_matcher.match(_fingerprint(), [_entry(data_category="dns_logs")]) == []


def test_unknown_sample_data_category_does_not_veto_a_logsource_match():
    """The data category is a coarser signal; not knowing it should not block."""
    candidates = taxonomy_matcher.match(_fingerprint(data_category=None), [_entry()])

    assert len(candidates) == 1


def test_curator_confidence_is_a_ceiling():
    """A perfect structural match cannot score above what the author claimed."""
    candidates = taxonomy_matcher.match(_fingerprint(), [_entry(confidence=0.5)])

    assert candidates[0].confidence <= 0.5


def test_fields_resolve_through_ecs_like_the_sigma_matcher():
    entry = _entry(required_fields=["source.ip"])

    candidate = taxonomy_matcher.match(_fingerprint(), [entry])[0]

    assert candidate.matched_fields == {"source.ip": "ClientIP"}


def test_missing_required_field_is_flagged_as_not_feasible():
    entry = _entry(required_fields=["ClientIP", "SomethingAbsent"])

    candidate = taxonomy_matcher.match(_fingerprint(), [entry])[0]

    assert candidate.missing_fields == ["SomethingAbsent"]
    assert "NOT feasible as written" in candidate.reasoning
    assert candidate.confidence < 0.8


def test_entry_with_no_satisfiable_field_is_dropped():
    entry = _entry(required_fields=["Absent1", "Absent2"])

    assert taxonomy_matcher.match(_fingerprint(), [entry]) == []


def test_assumptions_are_carried_onto_the_candidate():
    entry = _entry(assumptions=["the query string is URL-decoded at ingest"])

    candidate = taxonomy_matcher.match(_fingerprint(), [entry])[0]

    assert candidate.assumptions == ["the query string is URL-decoded at ingest"]
    assert "1 documented assumption" in candidate.reasoning


def test_min_confidence_filters():
    assert taxonomy_matcher.match(_fingerprint(), [_entry()], min_confidence=0.95) == []


def test_shipped_seed_entries_match_the_cloudflare_fixture():
    """The Phase 0 seed entries must still resolve against the sample they were written for."""
    from pathlib import Path

    from engine.ingestion import parser
    from engine.profiling.data_classifier import classify
    from engine.profiling.field_profiler import build_fingerprint, profile_fields
    from scripts.seed_taxonomy import DEFAULT_SEED_FILE

    fixture = Path(__file__).parent / "fixtures" / "cloudflare_waf_firewall_events.csv"
    sample = parser.parse(fixture)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    fingerprint = build_fingerprint(
        profiles, classify(sample.field_names), record_count=sample.record_count
    )

    entries = taxonomy_store.load_entries_from_json(DEFAULT_SEED_FILE)
    candidates = taxonomy_matcher.match(fingerprint, entries)

    assert {candidate.rule_ref for candidate in candidates} == {
        "internal:cloudflare-waf-sqli",
        "internal:cloudflare-waf-credential-stuffing",
    }
    assert all(not candidate.missing_fields for candidate in candidates)


# ----------------------------------------------------------- authoring workflow


@pytest.fixture()
def db_path(tmp_path):
    path = tmp_path / "engine.db"
    db.init_db(path)
    return path


def test_template_is_a_valid_entry(tmp_path, capsys):
    assert taxonomy_cli.main(["template"]) == 0
    written = tmp_path / "template.json"
    written.write_text(capsys.readouterr().out, encoding="utf-8")

    entries = taxonomy_store.load_entries_from_json(written)

    assert len(entries) == 1
    assert entries[0].slug == "vendor-product-behavior"


def test_import_then_list_then_export_round_trips(tmp_path, db_path, capsys):
    source = tmp_path / "entry.json"
    source.write_text(json.dumps({"entries": [_entry().model_dump()]}), encoding="utf-8")

    assert taxonomy_cli.main(["--db", str(db_path), "import", str(source)]) == 0
    assert "inserted cloudflare-test" in capsys.readouterr().out

    assert taxonomy_cli.main(["--db", str(db_path), "list"]) == 0
    assert "cloudflare-test" in capsys.readouterr().out

    exported = tmp_path / "export.json"
    assert taxonomy_cli.main(["--db", str(db_path), "export", str(exported)]) == 0
    capsys.readouterr()

    reloaded = taxonomy_store.load_entries_from_json(exported)
    assert reloaded[0].slug == "cloudflare-test"
    assert reloaded[0].required_fields == ["ClientIP", "Action"]


def test_import_is_idempotent(tmp_path, db_path, capsys):
    source = tmp_path / "entry.json"
    source.write_text(json.dumps({"entries": [_entry().model_dump()]}), encoding="utf-8")

    taxonomy_cli.main(["--db", str(db_path), "import", str(source)])
    taxonomy_cli.main(["--db", str(db_path), "import", str(source)])
    output = capsys.readouterr().out

    assert "updated cloudflare-test" in output.replace("  ", " ")
    with db.connection(db_path) as conn:
        assert taxonomy_store.count(conn) == 1


def test_validate_warns_about_entries_that_parse_but_disappoint(tmp_path, capsys):
    source = tmp_path / "weak.json"
    source.write_text(
        json.dumps({"entries": [{
            "slug": "weak", "name": "Weak entry", "suggested_rule_type": "magic",
        }]}),
        encoding="utf-8",
    )

    assert taxonomy_cli.main(["validate", str(source)]) == 0
    output = capsys.readouterr().out

    assert "not a known type" in output
    assert "no required_fields" in output
    assert "will match every sample" in output


def test_validate_rejects_an_unknown_key(tmp_path, capsys):
    source = tmp_path / "typo.json"
    source.write_text(
        json.dumps({"entries": [{"slug": "x", "name": "X", "assumption": "typo"}]}), encoding="utf-8"
    )

    assert taxonomy_cli.main(["validate", str(source)]) == 1


def test_delete_removes_an_entry(tmp_path, db_path, capsys):
    source = tmp_path / "entry.json"
    source.write_text(json.dumps({"entries": [_entry().model_dump()]}), encoding="utf-8")
    taxonomy_cli.main(["--db", str(db_path), "import", str(source)])

    assert taxonomy_cli.main(["--db", str(db_path), "delete", "cloudflare-test"]) == 0
    assert taxonomy_cli.main(["--db", str(db_path), "delete", "cloudflare-test"]) == 1
