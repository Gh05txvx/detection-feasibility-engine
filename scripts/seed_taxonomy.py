"""Load internal taxonomy entries from a JSON seed file into the database.

Idempotent — entries are upserted by slug, so editing the seed file and
re-running updates rows in place rather than duplicating them. This is the
Phase 0 structural-proof loader and the starting point for the Phase 3
taxonomy-authoring workflow.

Usage::

    python scripts/seed_taxonomy.py
    python scripts/seed_taxonomy.py --dry-run
    python scripts/seed_taxonomy.py --seed-file path\\to\\other.json --db path\\to\\other.db
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from engine.storage import db, taxonomy_store  # noqa: E402  (needs sys.path set first)
from engine.storage.taxonomy_store import load_entries_from_json  # noqa: E402

DEFAULT_SEED_FILE = REPO_ROOT / "scripts" / "seeds" / "internal_taxonomy.json"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default=None, help=f"SQLite file to seed (default: {db.DEFAULT_DB_PATH})")
    parser.add_argument("--seed-file", default=None, help=f"JSON seed file (default: {DEFAULT_SEED_FILE})")
    parser.add_argument("--dry-run", action="store_true", help="validate the seed file, write nothing")
    args = parser.parse_args(argv)

    seed_file = Path(args.seed_file) if args.seed_file else DEFAULT_SEED_FILE
    if not seed_file.exists():
        print(f"seed file not found: {seed_file}", file=sys.stderr)
        return 1

    try:
        entries = load_entries_from_json(seed_file)
    except Exception as exc:  # noqa: BLE001 - surface any parse/validation error verbatim
        print(f"invalid seed file {seed_file}: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print(f"{seed_file}: {len(entries)} entr(ies) valid")
        for entry in entries:
            print(f"  {entry.slug:<40} {entry.name}")
        return 0

    db_path = Path(args.db) if args.db else db.DEFAULT_DB_PATH
    db.init_db(db_path)

    inserted = updated = 0
    with db.connection(db_path) as conn:
        for entry in entries:
            existed = taxonomy_store.get(conn, entry.slug) is not None
            taxonomy_store.upsert(conn, entry)
            if existed:
                updated += 1
                print(f"  updated  {entry.slug}")
            else:
                inserted += 1
                print(f"  inserted {entry.slug}")
        total = taxonomy_store.count(conn)

    print(f"taxonomy seeded from {seed_file.name}: {inserted} inserted, {updated} updated, {total} total")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
