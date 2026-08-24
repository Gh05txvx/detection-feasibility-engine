"""Author and inspect the internal detection taxonomy.

The taxonomy is the half of matching that grows per project (BLUEPRINT 5.3b), so
adding an entry has to be easy enough that an analyst actually does it at the end
of a project instead of leaving the knowledge in their head.

The workflow is template -> edit -> import:

    python scripts/taxonomy.py template > new-entry.json
    # fill it in
    python scripts/taxonomy.py validate new-entry.json
    python scripts/taxonomy.py import new-entry.json

Import upserts by slug, so re-importing an edited file updates in place. Export
writes every entry back out in the same format, which is how the taxonomy gets
version-controlled or handed to another engineer.

    python scripts/taxonomy.py list
    python scripts/taxonomy.py show cloudflare-waf-sqli
    python scripts/taxonomy.py export scripts/seeds/internal_taxonomy.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from engine.storage import db, taxonomy_store  # noqa: E402  (needs sys.path set first)
from engine.storage.taxonomy_store import (  # noqa: E402
    TaxonomyEntry,
    dump_entries_to_json,
    load_entries_from_json,
)

TEMPLATE = {
    "source": "Describe where this entry came from: which project, which analyst, which incident.",
    "entries": [
        {
            "slug": "vendor-product-behavior",
            "name": "Vendor Product - the behavior in one line",
            "description": "What this detects and how you know, in the words you would use to a colleague.",
            "logsource_category": "webserver",
            "logsource_product": "vendor",
            "logsource_service": "data_stream",
            "data_category": "application_logs",
            "required_fields": ["FieldTheLogicCannotWorkWithout"],
            "optional_fields": ["FieldsThatSharpenIt"],
            "detection_logic": {
                "selection": {"SomeField": ["value"]},
                "condition": "selection",
            },
            "assumptions": [
                "Normalization the ingest pipeline must perform for this logic to hold.",
                "Client-specific values to confirm at onboarding.",
            ],
            "mitre_techniques": ["T1190"],
            "suggested_rule_type": "custom_query",
            "confidence": 0.7,
            "false_positives": ["Where this fires legitimately."],
            "source_project": "project name",
            "author": "your name",
            "notes": "Anything the next person needs to know before trusting this.",
        }
    ],
}

_RULE_TYPES = (
    "custom_query", "eql", "threshold", "esql", "indicator_match", "new_terms", "machine_learning",
)
_DATA_CATEGORIES = (
    "network_logs", "endpoint_data", "authentication_logs", "application_logs",
    "dns_logs", "system_logs", "threat_intel_feed",
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--db", default=None, help=f"SQLite file (default: {db.DEFAULT_DB_PATH})")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="list every entry")
    subparsers.add_parser("template", help="print a blank entry to fill in")

    show = subparsers.add_parser("show", help="print one entry as JSON")
    show.add_argument("slug")

    validate = subparsers.add_parser("validate", help="check a file without writing")
    validate.add_argument("path")

    import_cmd = subparsers.add_parser("import", help="validate and upsert entries from a file")
    import_cmd.add_argument("path")

    export = subparsers.add_parser("export", help="write every entry to a file, or stdout")
    export.add_argument("path", nargs="?", default=None)

    delete = subparsers.add_parser("delete", help="remove one entry")
    delete.add_argument("slug")

    args = parser.parse_args(argv)
    db_path = Path(args.db) if args.db else db.DEFAULT_DB_PATH

    if args.command == "template":
        print(json.dumps(TEMPLATE, indent=2, ensure_ascii=False))
        print(
            f"\n# suggested_rule_type: {', '.join(_RULE_TYPES)}"
            f"\n# data_category      : {', '.join(_DATA_CATEGORIES)}",
            file=sys.stderr,
        )
        return 0

    if args.command == "validate":
        return _validate(Path(args.path))

    db.init_db(db_path)
    with db.connection(db_path) as conn:
        if args.command == "list":
            return _list(conn)
        if args.command == "show":
            return _show(conn, args.slug)
        if args.command == "import":
            return _import(conn, Path(args.path))
        if args.command == "export":
            return _export(conn, Path(args.path) if args.path else None)
        if args.command == "delete":
            return _delete(conn, args.slug)

    parser.error(f"unknown command {args.command}")
    return 2


def _validate(path: Path) -> int:
    if not path.exists():
        print(f"file not found: {path}", file=sys.stderr)
        return 1
    try:
        entries = load_entries_from_json(path)
    except Exception as exc:  # noqa: BLE001 - report the validation error verbatim
        print(f"invalid: {exc}", file=sys.stderr)
        return 1

    problems = [problem for entry in entries for problem in _lint(entry)]
    for problem in problems:
        print(f"  warning: {problem}")

    print(f"{path.name}: {len(entries)} entr(ies) parse cleanly"
          + (f", {len(problems)} warning(s)" if problems else ""))
    return 0


def _lint(entry: TaxonomyEntry) -> list[str]:
    """Non-fatal checks: things that parse but will disappoint later."""
    problems: list[str] = []
    if entry.suggested_rule_type and entry.suggested_rule_type not in _RULE_TYPES:
        problems.append(f"{entry.slug}: suggested_rule_type '{entry.suggested_rule_type}' is not a known type")
    if entry.data_category and entry.data_category not in _DATA_CATEGORIES:
        problems.append(f"{entry.slug}: data_category '{entry.data_category}' is not a known category")
    if not entry.required_fields:
        problems.append(f"{entry.slug}: no required_fields, so feasibility cannot be checked against a sample")
    if not entry.mitre_techniques:
        problems.append(f"{entry.slug}: no mitre_techniques, so the runbook will have no ATT&CK mapping")
    if not (entry.logsource_category or entry.logsource_product):
        problems.append(f"{entry.slug}: no logsource category or product, so it will match every sample")
    return problems


def _list(conn) -> int:
    entries = taxonomy_store.list_entries(conn)
    if not entries:
        print("taxonomy is empty. Start with: python scripts/taxonomy.py template")
        return 0

    print(f"{'slug':<36} {'logsource':<34} {'conf':>5}  techniques")
    print(f"{'-' * 36} {'-' * 34} {'-' * 5}  {'-' * 24}")
    for entry in entries:
        logsource = "/".join(
            part or "-" for part in
            (entry.logsource_category, entry.logsource_product, entry.logsource_service)
        )
        print(
            f"{entry.slug:<36} {logsource[:34]:<34} {entry.confidence:>5.2f}  "
            f"{', '.join(entry.mitre_techniques) or '-'}"
        )
    print(f"\n{len(entries)} entr(ies)")
    return 0


def _show(conn, slug: str) -> int:
    entry = taxonomy_store.get(conn, slug)
    if entry is None:
        print(f"no entry with slug '{slug}'", file=sys.stderr)
        return 1
    print(json.dumps(entry.model_dump(), indent=2, ensure_ascii=False))
    return 0


def _import(conn, path: Path) -> int:
    if not path.exists():
        print(f"file not found: {path}", file=sys.stderr)
        return 1
    try:
        entries = load_entries_from_json(path)
    except Exception as exc:  # noqa: BLE001
        print(f"invalid: {exc}", file=sys.stderr)
        return 1

    for problem in (problem for entry in entries for problem in _lint(entry)):
        print(f"  warning: {problem}")

    inserted = updated = 0
    for entry in entries:
        existed = taxonomy_store.get(conn, entry.slug) is not None
        taxonomy_store.upsert(conn, entry)
        if existed:
            updated += 1
            print(f"  updated  {entry.slug}")
        else:
            inserted += 1
            print(f"  inserted {entry.slug}")

    print(f"{inserted} inserted, {updated} updated, {taxonomy_store.count(conn)} total")
    return 0


def _export(conn, path: Path | None) -> int:
    entries = taxonomy_store.list_entries(conn)
    payload = dump_entries_to_json(entries)
    if path is None:
        print(payload)
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    print(f"exported {len(entries)} entr(ies) to {path}")
    return 0


def _delete(conn, slug: str) -> int:
    if taxonomy_store.delete(conn, slug):
        print(f"deleted {slug}")
        return 0
    print(f"no entry with slug '{slug}'", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
