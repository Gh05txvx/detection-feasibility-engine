"""Run the engine against one log sample and print what it found.

    python scripts/cli.py tests/fixtures/cloudflare_waf_firewall_events.csv

Phase 1 scope: ingestion -> profiling -> ECS gap -> Sigma matching. The internal
taxonomy (Phase 3), the hypothesis module for the NO MATCH path (Phase 2), rule
type classification (Phase 3), and backtesting (Phase 4) are not wired in yet;
where they would speak, the output says so rather than staying silent.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from engine.ingestion import parser as ingestion  # noqa: E402  (needs sys.path set first)
from engine.matching import sigma_matcher  # noqa: E402
from engine.matching.candidate import MatchCandidate  # noqa: E402
from engine.profiling import ecs_gap  # noqa: E402
from engine.profiling.data_classifier import classify  # noqa: E402
from engine.profiling.field_profiler import LogFingerprint, build_fingerprint, profile_fields  # noqa: E402

RULE = "-" * 78


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)

    try:
        sample = ingestion.parse(args.sample, limit=args.limit)
    except ingestion.ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    profiles = profile_fields(sample.records, field_names=sample.field_names)
    classification = classify(sample.field_names)

    _status("loading integration index (first run builds it, ~1 min)...", args)
    integration_index = ecs_gap.load_index(args.integrations, rebuild=args.rebuild_index)
    gap = ecs_gap.analyse(profiles, integration_index, product_hint=classification.inferred_product)

    fingerprint = build_fingerprint(
        profiles,
        classification,
        record_count=sample.record_count,
        integration_name=gap.integration.name if gap.integration else None,
    )

    _status("loading sigma rule index (first run builds it, ~30 s)...", args)
    rule_index = sigma_matcher.load_rule_index(args.sigma_corpus, rebuild=args.rebuild_index)
    candidates: list[MatchCandidate] = []
    if rule_index is not None:
        candidates = sigma_matcher.match(fingerprint, rule_index, min_confidence=args.min_confidence)

    if args.json:
        _emit_json(sample, fingerprint, gap, candidates, rule_index)
        return 0

    _report_sample(sample)
    _report_fingerprint(fingerprint)
    _report_fields(fingerprint)
    _report_ecs_gap(gap)
    _report_candidates(candidates, rule_index, fingerprint, args.top)
    return 0


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    arg_parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    arg_parser.add_argument("sample", help="path to the raw log sample (CSV / JSON / JSONL)")
    arg_parser.add_argument("--limit", type=int, default=None, help="read at most N records")
    arg_parser.add_argument("--top", type=int, default=10, help="show at most N match candidates (default 10)")
    arg_parser.add_argument(
        "--min-confidence", type=float, default=0.4, help="drop candidates below this confidence (default 0.4)"
    )
    arg_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of a report")
    arg_parser.add_argument("--rebuild-index", action="store_true", help="rebuild the cached corpus indexes")
    arg_parser.add_argument("--sigma-corpus", default=None, help="path to the Sigma rules directory")
    arg_parser.add_argument("--integrations", default=None, help="path to the elastic/integrations clone")
    return arg_parser.parse_args(argv)


def _status(message: str, args: argparse.Namespace) -> None:
    if not args.json:
        print(f"  ... {message}", file=sys.stderr)


# ------------------------------------------------------------------ rendering


def _report_sample(sample) -> None:
    print(RULE)
    print(f"SAMPLE  {sample.path}")
    print(RULE)
    detail = f"format {sample.format.value} | encoding {sample.encoding}"
    if sample.delimiter:
        detail += f" | delimiter {sample.delimiter!r}"
    print(f"  {detail}")
    print(f"  {sample.record_count} records, {len(sample.field_names)} fields"
          + (" (truncated by --limit)" if sample.truncated else ""))

    decoded = sum(1 for record in sample.records if record.raw_fields)
    if decoded:
        print(f"  {decoded} record(s) had URL-encoded values decoded at ingestion")
    for problem in sample.problems:
        print(f"  ! {problem}")


def _report_fingerprint(fingerprint: LogFingerprint) -> None:
    print()
    print(RULE)
    print("FINGERPRINT")
    print(RULE)
    triple = " / ".join(
        value or "?" for value in
        (fingerprint.inferred_category, fingerprint.inferred_product, fingerprint.inferred_service)
    )
    print(f"  logsource      {triple}   (category / product / service)")
    print(f"  data category  {fingerprint.data_category.value if fingerprint.data_category else 'unknown'}")
    print(f"  confidence     {fingerprint.classification_confidence}")
    for line in fingerprint.classification_evidence:
        print(f"  evidence       {line}")


def _report_fields(fingerprint: LogFingerprint) -> None:
    print()
    print(RULE)
    print("FIELD PROFILE")
    print(RULE)
    header = f"  {'field':<26} {'type':<10} {'card':>5} {'null':>6}  {'entity':<13} ecs"
    print(header)
    print(f"  {'-' * 26} {'-' * 10} {'-' * 5} {'-' * 6}  {'-' * 13} {'-' * 24}")
    for profile in fingerprint.profiles:
        if profile.is_ecs_compliant:
            ecs = "ok"
        elif profile.suggested_ecs_field:
            ecs = f"-> {profile.suggested_ecs_field}"
        else:
            ecs = "unmapped"
        print(
            f"  {_clip(profile.field_name, 26):<26} {profile.dtype:<10} {profile.cardinality:>5} "
            f"{profile.null_rate:>6.2f}  {(profile.entity_type.value if profile.entity_type else '-'):<13} {ecs}"
        )


def _report_ecs_gap(gap) -> None:
    print()
    print(RULE)
    print("ECS GAP")
    print(RULE)
    if gap.integration:
        print(f"  official integration   {gap.integration.name}")
        if gap.integration.title:
            print(f"  package title          {gap.integration.title}")
        print(f"  field coverage         {gap.integration.coverage:.0%} "
              f"({len(gap.integration.matched_fields)} fields recognised)")
    else:
        print("  official integration   none matched")

    print(f"  already ECS            {len(gap.compliant_fields)}")
    print(f"  mapped by integration  {len(gap.mapped_fields)}")
    print(f"  heuristic suggestion   {len(gap.suggested_fields)}")
    if gap.unmapped_fields:
        print(f"  unmapped               {len(gap.unmapped_fields)}: {', '.join(gap.unmapped_fields)}")
    for note in gap.notes:
        print(f"  note: {note}")


def _report_candidates(
    candidates: Sequence[MatchCandidate],
    rule_index,
    fingerprint: LogFingerprint,
    top: int,
) -> None:
    print()
    print(RULE)
    print("SIGMA MATCH CANDIDATES")
    print(RULE)

    if rule_index is None:
        print("  Sigma corpus not found. Run scripts\\setup.ps1 to clone it.")
        return

    print(f"  corpus: {len(rule_index.rules)} rules"
          + (f", {rule_index.parse_errors} unparsable" if rule_index.parse_errors else ""))

    if not candidates:
        print()
        print("  NO MATCH.")
        if fingerprint.inferred_category is None and fingerprint.inferred_product is None:
            print("  The log source could not be classified, so no rule's logsource could be confirmed.")
            print("  Add a signature in engine/profiling/data_classifier.py once this source is known.")
        else:
            print("  No rule's logsource and field requirements are both satisfied by this sample.")
        print("  'No match' is not 'not detectable' (BLUEPRINT §10). The structured rejection")
        print("  reasoning that belongs here is the Phase 2 hypothesis module, not built yet.")
        return

    print(f"  {len(candidates)} candidate(s) above the confidence floor; showing {min(top, len(candidates))}")
    for position, candidate in enumerate(candidates[:top], start=1):
        print()
        print(f"  {position:>2}. [{candidate.confidence:.2f}] {candidate.title}")
        print(f"      {candidate.rule_ref}   level={candidate.level or '?'}")
        if candidate.rule_path:
            print(f"      {candidate.rule_path}")
        if candidate.mitre_techniques:
            print(f"      mitre: {', '.join(candidate.mitre_techniques)}")
        print(f"      why: {candidate.reasoning}")

    print()
    print("  Rule type selection (Phase 3), backtest and noise estimate (Phase 4), and the")
    print("  runbook (Phase 5) are not built yet. Every candidate above still needs analyst review.")


def _emit_json(sample, fingerprint, gap, candidates, rule_index) -> None:
    payload = {
        "sample": {
            "path": sample.path,
            "format": sample.format.value,
            "encoding": sample.encoding,
            "record_count": sample.record_count,
            "truncated": sample.truncated,
            "problems": sample.problems,
        },
        "fingerprint": fingerprint.model_dump(mode="json"),
        "ecs_gap": gap.model_dump(mode="json"),
        "sigma_corpus_rules": len(rule_index.rules) if rule_index else 0,
        "candidates": [candidate.model_dump(mode="json") for candidate in candidates],
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _clip(text: str, width: int) -> str:
    # ASCII only: this prints to a Windows console whose code page may not be UTF-8.
    return text if len(text) <= width else text[: width - 3] + "..."


if __name__ == "__main__":
    raise SystemExit(main())
