"""Storage layer tests — the only engine code that exists in Phase 0."""

from __future__ import annotations

import sqlite3

import pytest

from engine.storage import db, taxonomy_store
from engine.storage.taxonomy_store import TaxonomyEntry, load_entries_from_json
from scripts.seed_taxonomy import DEFAULT_SEED_FILE


@pytest.fixture()
def conn(tmp_path):
    db.init_db(tmp_path / "engine.db")
    with db.connection(tmp_path / "engine.db") as connection:
        yield connection


def _entry(**overrides) -> TaxonomyEntry:
    defaults = dict(
        slug="test-entry",
        name="Test entry",
        logsource_product="cloudflare",
        logsource_category="webserver",
        data_category="application_logs",
        required_fields=["ClientIP", "ClientRequestQuery"],
        detection_logic={"selection": {"Action": ["block"]}, "condition": "selection"},
        mitre_techniques=["T1190"],
        suggested_rule_type="custom_query",
        confidence=0.8,
    )
    defaults.update(overrides)
    return TaxonomyEntry(**defaults)


def test_migrate_creates_both_tables(conn):
    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    }
    assert {"taxonomy_entries", "job_runs"} <= tables
    assert db.get_version(conn) == db.SCHEMA_VERSION


def test_migrate_is_idempotent(conn):
    assert db.migrate(conn) == db.SCHEMA_VERSION
    assert db.migrate(conn) == db.SCHEMA_VERSION


def test_migrate_resumes_from_an_older_version(tmp_path):
    """A database left at an earlier version picks up the migrations it missed."""
    path = tmp_path / "old.db"
    with db.connection(path) as connection:
        first_version, first_statements = db.MIGRATIONS[0]
        with db.transaction(connection):
            for statement in first_statements:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {first_version}")
        assert db.get_version(connection) == first_version

        assert db.migrate(connection) == db.SCHEMA_VERSION
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(taxonomy_entries)")}
        assert "assumptions" in columns
        job_columns = {row["name"] for row in connection.execute("PRAGMA table_info(job_runs)")}
        assert "stage" in job_columns


def test_migrations_are_listed_in_ascending_order():
    """Out of order, a later version applied first makes the earlier one unreachable."""
    versions = [version for version, _ in db.MIGRATIONS]

    assert versions == sorted(versions)


def test_upsert_roundtrips_json_columns(conn):
    taxonomy_store.upsert(conn, _entry())

    stored = taxonomy_store.get(conn, "test-entry")
    assert stored is not None
    assert stored.required_fields == ["ClientIP", "ClientRequestQuery"]
    assert stored.detection_logic["selection"] == {"Action": ["block"]}
    assert stored.mitre_techniques == ["T1190"]
    assert stored.created_at is not None


def test_upsert_updates_in_place_by_slug(conn):
    first_id = taxonomy_store.upsert(conn, _entry())
    second_id = taxonomy_store.upsert(conn, _entry(name="Renamed", confidence=0.4))

    assert first_id == second_id
    assert taxonomy_store.count(conn) == 1
    stored = taxonomy_store.get(conn, "test-entry")
    assert stored.name == "Renamed"
    assert stored.confidence == pytest.approx(0.4)


def test_delete_removes_entry(conn):
    taxonomy_store.upsert(conn, _entry())
    assert taxonomy_store.delete(conn, "test-entry") is True
    assert taxonomy_store.delete(conn, "test-entry") is False
    assert taxonomy_store.count(conn) == 0


def test_confidence_outside_range_is_rejected():
    with pytest.raises(ValueError):
        _entry(confidence=1.4)


def test_unknown_key_is_rejected(conn):
    """A mistyped key in a hand-written seed file must fail, not vanish."""
    with pytest.raises(ValueError):
        _entry(assumption="typo, should be 'assumptions'")


def test_assumptions_roundtrip(conn):
    taxonomy_store.upsert(conn, _entry(assumptions=["query string is URL-decoded at ingestion"]))
    stored = taxonomy_store.get(conn, "test-entry")
    assert stored.assumptions == ["query string is URL-decoded at ingestion"]


def test_job_runs_rejects_unknown_status(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO job_runs (job_id, filename, status, created_at) VALUES (?, ?, ?, ?)",
            ("job-1", "sample.csv", "not-a-status", "2026-03-11T09:00:00+00:00"),
        )


def test_transaction_rolls_back_on_error(conn):
    taxonomy_store.upsert(conn, _entry())
    with pytest.raises(sqlite3.IntegrityError):
        with db.transaction(conn):
            conn.execute("DELETE FROM taxonomy_entries")
            conn.execute(
                "INSERT INTO job_runs (job_id, filename, status, created_at) VALUES (?, ?, ?, ?)",
                ("job-2", "sample.csv", "bogus", "2026-03-11T09:00:00+00:00"),
            )
    assert taxonomy_store.count(conn) == 1


def test_shipped_seed_file_is_valid_and_loadable(conn):
    entries = load_entries_from_json(DEFAULT_SEED_FILE)

    assert len(entries) >= 2
    assert len({entry.slug for entry in entries}) == len(entries)
    for entry in entries:
        taxonomy_store.upsert(conn, entry)
    assert taxonomy_store.count(conn) == len(entries)
