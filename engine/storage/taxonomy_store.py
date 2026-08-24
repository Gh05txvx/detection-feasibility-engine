"""CRUD for the internal detection taxonomy (docs/BLUEPRINT.md 5.3b).

The internal taxonomy is the half of the matching engine that Sigma does not
cover: proprietary apps, custom APIs, niche vendors. Entries are written by
analysts out of real project work, so every row carries provenance
(``source_project``, ``author``) next to its matching data.

Matching against these entries is Phase 3 (``engine/matching/taxonomy_matcher.py``).
This module only stores and retrieves them.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from engine.storage.db import transaction

# Columns written on insert/update. `created_at`/`updated_at` are handled
# separately, and `id` is assigned by SQLite.
_COLUMNS: tuple[str, ...] = (
    "slug",
    "name",
    "description",
    "logsource_category",
    "logsource_product",
    "logsource_service",
    "data_category",
    "required_fields",
    "optional_fields",
    "detection_logic",
    "assumptions",
    "mitre_techniques",
    "suggested_rule_type",
    "confidence",
    "false_positives",
    "source_project",
    "author",
    "notes",
)

# Stored as JSON text, decoded back into list/dict on read.
_JSON_LIST_FIELDS = (
    "required_fields",
    "optional_fields",
    "assumptions",
    "mitre_techniques",
    "false_positives",
)
_JSON_DICT_FIELDS = ("detection_logic",)


class TaxonomyEntry(BaseModel):
    """One internal taxonomy entry.

    ``data_category`` and ``suggested_rule_type`` are plain strings for now;
    they tighten to the ``DataCategory`` (Phase 1) and ``ElasticRuleType``
    (Phase 3) enums once those modules exist. Allowed values today:

    * ``data_category``: network_logs, endpoint_data, authentication_logs,
      application_logs, dns_logs, system_logs, threat_intel_feed
    * ``suggested_rule_type``: custom_query, eql, threshold, esql,
      indicator_match, new_terms, machine_learning

    Unknown keys are rejected rather than ignored: a seed file is hand-written,
    and a mistyped key that silently disappears is worse than a loud failure.
    """

    model_config = ConfigDict(extra="forbid")

    slug: str
    name: str
    description: str = ""

    logsource_category: str | None = None
    logsource_product: str | None = None
    logsource_service: str | None = None
    data_category: str | None = None

    required_fields: list[str] = Field(default_factory=list)
    optional_fields: list[str] = Field(default_factory=list)
    detection_logic: dict[str, Any] = Field(default_factory=dict)
    # Preconditions the detection logic depends on: normalization ingestion has
    # to perform, client-specific values to confirm at onboarding.
    assumptions: list[str] = Field(default_factory=list)

    mitre_techniques: list[str] = Field(default_factory=list)
    suggested_rule_type: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    false_positives: list[str] = Field(default_factory=list)

    source_project: str | None = None
    author: str | None = None
    notes: str = ""

    # Set by the database, not by the caller.
    id: int | None = None
    created_at: str | None = None
    updated_at: str | None = None


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _to_row(entry: TaxonomyEntry) -> dict[str, Any]:
    row = entry.model_dump(include=set(_COLUMNS))
    for field in _JSON_LIST_FIELDS + _JSON_DICT_FIELDS:
        row[field] = json.dumps(row[field], ensure_ascii=False, sort_keys=False)
    return row


def _from_row(row: sqlite3.Row) -> TaxonomyEntry:
    data = dict(row)
    for field in _JSON_LIST_FIELDS + _JSON_DICT_FIELDS:
        data[field] = json.loads(data[field])
    return TaxonomyEntry(**data)


def upsert(conn: sqlite3.Connection, entry: TaxonomyEntry) -> int:
    """Insert the entry, or update the existing one with the same slug.

    Returns the row id. Re-running a seed file is therefore idempotent.
    """
    now = _utcnow()
    row = _to_row(entry)
    placeholders = ", ".join("?" for _ in _COLUMNS)
    updates = ", ".join(f"{column} = excluded.{column}" for column in _COLUMNS if column != "slug")

    sql = (
        f"INSERT INTO taxonomy_entries ({', '.join(_COLUMNS)}, created_at, updated_at) "
        f"VALUES ({placeholders}, ?, ?) "
        f"ON CONFLICT(slug) DO UPDATE SET {updates}, updated_at = excluded.updated_at"
    )
    values = [row[column] for column in _COLUMNS] + [now, now]

    with transaction(conn):
        conn.execute(sql, values)
    return int(conn.execute("SELECT id FROM taxonomy_entries WHERE slug = ?", (entry.slug,)).fetchone()[0])


def get(conn: sqlite3.Connection, slug: str) -> TaxonomyEntry | None:
    """Return the entry with this slug, or None."""
    row = conn.execute("SELECT * FROM taxonomy_entries WHERE slug = ?", (slug,)).fetchone()
    return _from_row(row) if row else None


def list_entries(conn: sqlite3.Connection) -> list[TaxonomyEntry]:
    """Return every entry, ordered by slug."""
    rows = conn.execute("SELECT * FROM taxonomy_entries ORDER BY slug").fetchall()
    return [_from_row(row) for row in rows]


def count(conn: sqlite3.Connection) -> int:
    """Return how many entries the taxonomy holds."""
    return int(conn.execute("SELECT count(*) FROM taxonomy_entries").fetchone()[0])


def delete(conn: sqlite3.Connection, slug: str) -> bool:
    """Delete the entry with this slug. Returns True if a row was removed."""
    with transaction(conn):
        cursor = conn.execute("DELETE FROM taxonomy_entries WHERE slug = ?", (slug,))
    return cursor.rowcount > 0


def load_entries_from_json(path: str | Path) -> list[TaxonomyEntry]:
    """Parse and validate a taxonomy file, failing loudly on a bad entry.

    The file format is ``{"entries": [...]}``, optionally with any other
    top-level keys for human notes. Shared by the setup-time seeder and the
    authoring workflow so both reject the same mistakes.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    raw_entries = payload.get("entries", [])
    if not raw_entries:
        raise ValueError(f"{path} has no 'entries'")
    return [TaxonomyEntry(**raw) for raw in raw_entries]


def dump_entries_to_json(entries: list[TaxonomyEntry], *, source: str = "") -> str:
    """Render entries back to the seed-file format, for export and review."""
    payload = {
        "source": source or "Exported from the internal taxonomy database.",
        "entries": [
            entry.model_dump(exclude={"id", "created_at", "updated_at"}) for entry in entries
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
