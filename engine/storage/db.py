"""SQLite connection handling and schema migrations.

Two tables live here:

* ``taxonomy_entries`` — the internal, hand-curated detection taxonomy that
  covers what the public Sigma corpus does not (docs/BLUEPRINT.md 5.3b).
* ``job_runs`` — job/run history for the local web UI (docs/BLUEPRINT.md 8.5).
  Designed now, per the Phase 0 checklist, but unused until Phase 6.

Schema changes are append-only: add a new ``(version, statements)`` tuple to
``MIGRATIONS``; never edit one that has already been applied anywhere. The
applied version is tracked in SQLite's built-in ``PRAGMA user_version``.

Usage::

    python -m engine.storage.db --init      # create or upgrade the schema
    python -m engine.storage.db --status    # report version + row counts
"""

from __future__ import annotations

import argparse
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = REPO_ROOT / "data" / "engine.db"

# (version, statements applied in order within one transaction)
MIGRATIONS: Sequence[tuple[int, Sequence[str]]] = (
    (
        1,
        (
            """
            CREATE TABLE taxonomy_entries (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                slug                TEXT    NOT NULL UNIQUE,
                name                TEXT    NOT NULL,
                description         TEXT    NOT NULL DEFAULT '',

                -- logsource selectors, deliberately mirroring Sigma's logsource
                -- block so a LogFingerprint can be matched against the internal
                -- taxonomy and the Sigma corpus with the same fields
                logsource_category  TEXT,
                logsource_product   TEXT,
                logsource_service   TEXT,
                data_category       TEXT,

                -- feasibility inputs
                required_fields     TEXT    NOT NULL DEFAULT '[]',
                optional_fields     TEXT    NOT NULL DEFAULT '[]',
                detection_logic     TEXT    NOT NULL DEFAULT '{}',

                -- carried into the runbook when this entry matches
                mitre_techniques    TEXT    NOT NULL DEFAULT '[]',
                suggested_rule_type TEXT,
                confidence          REAL    NOT NULL DEFAULT 0.5,
                false_positives     TEXT    NOT NULL DEFAULT '[]',

                -- provenance: the taxonomy grows one project at a time, so an
                -- entry has to say where it came from and who to ask about it
                source_project      TEXT,
                author              TEXT,
                notes               TEXT    NOT NULL DEFAULT '',

                created_at          TEXT    NOT NULL,
                updated_at          TEXT    NOT NULL,

                CHECK (confidence >= 0.0 AND confidence <= 1.0)
            )
            """,
            """
            CREATE INDEX idx_taxonomy_logsource
                ON taxonomy_entries (logsource_product, logsource_category)
            """,
            """
            CREATE INDEX idx_taxonomy_data_category
                ON taxonomy_entries (data_category)
            """,
            """
            CREATE TABLE job_runs (
                job_id       TEXT PRIMARY KEY,
                filename     TEXT NOT NULL,
                status       TEXT NOT NULL,
                created_at   TEXT NOT NULL,
                finished_at  TEXT,
                result_type  TEXT,
                result_path  TEXT,
                error        TEXT,

                CHECK (status IN ('queued', 'running', 'done', 'failed')),
                CHECK (result_type IS NULL OR result_type IN ('runbook', 'rejection_report'))
            )
            """,
            """
            CREATE INDEX idx_job_runs_created_at ON job_runs (created_at DESC)
            """,
            """
            CREATE INDEX idx_job_runs_status ON job_runs (status)
            """,
        ),
    ),
    (
        2,
        (
            # Preconditions an entry's detection logic depends on (normalization
            # the ingestion layer must do, client-specific values to confirm at
            # onboarding). Kept separate from `notes` because Phase 5 carries
            # these into the runbook as review items, and Phase 2 reads them as
            # onboarding requirements.
            """
            ALTER TABLE taxonomy_entries
                ADD COLUMN assumptions TEXT NOT NULL DEFAULT '[]'
            """,
        ),
    ),
)

SCHEMA_VERSION = max(version for version, _ in MIGRATIONS)


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open a connection with the conventions the rest of the engine expects.

    Autocommit (``isolation_level=None``) — transactions are explicit, via
    :func:`transaction`, so DDL and DML behave the same way.
    """
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def connection(db_path: str | Path | None = None) -> Iterator[sqlite3.Connection]:
    """Open a connection, closing it on the way out."""
    conn = connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Wrap a unit of work in BEGIN/COMMIT, rolling back on any exception."""
    conn.execute("BEGIN")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def get_version(conn: sqlite3.Connection) -> int:
    """Return the schema version currently applied to this database."""
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def migrate(conn: sqlite3.Connection) -> int:
    """Apply every migration newer than the database's current version."""
    current = get_version(conn)
    for version, statements in MIGRATIONS:
        if version <= current:
            continue
        with transaction(conn):
            for statement in statements:
                conn.execute(statement)
            # PRAGMA does not take bind parameters; version is an int literal.
            conn.execute(f"PRAGMA user_version = {int(version)}")
        current = version
    return current


def init_db(db_path: str | Path | None = None) -> Path:
    """Create or upgrade the database, returning the file it lives in."""
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    with connection(path) as conn:
        migrate(conn)
    return path


def _table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return {
        row["name"]: int(conn.execute(f"SELECT count(*) FROM {row['name']}").fetchone()[0])
        for row in rows
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default=None, help=f"SQLite file to use (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--init", action="store_true", help="create or upgrade the schema (default action)")
    parser.add_argument("--status", action="store_true", help="report schema version and row counts, no writes")
    args = parser.parse_args(argv)

    path = Path(args.db) if args.db else DEFAULT_DB_PATH

    if args.status and not args.init:
        if not path.exists():
            print(f"no database at {path} — run: python -m engine.storage.db --init")
            return 1
        with connection(path) as conn:
            print(f"database      : {path}")
            print(f"schema version: {get_version(conn)} (latest: {SCHEMA_VERSION})")
            for table, count in _table_counts(conn).items():
                print(f"  {table:<18} {count} row(s)")
        return 0

    with connection(path) as conn:
        before = get_version(conn)
        after = migrate(conn)
    if before == after:
        print(f"database up to date at schema v{after}: {path}")
    else:
        print(f"database migrated v{before} -> v{after}: {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
