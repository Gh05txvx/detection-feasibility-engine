"""Run the engine against one log sample and print what it found.

    python scripts/cli.py tests/fixtures/cloudflare_waf_firewall_events.csv

Orchestration lives in `engine/pipeline.py`; this file only parses arguments and
renders. Phases 0-5 are wired up: ingestion, profiling, ECS gap analysis,
matching against both the Sigma corpus and the internal taxonomy, Elastic rule
type selection, backtesting, and runbook generation, with the ABLE hypothesis
module on the no-match path.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from engine import pipeline  # noqa: E402  (needs sys.path set first)
from engine.classification import rule_type_classifier  # noqa: E402
from engine.hypothesis import report as rejection_report  # noqa: E402
from engine.ingestion import parser as ingestion  # noqa: E402
from engine.pipeline import PipelineResult  # noqa: E402
from engine.storage.taxonomy_store import TaxonomyEntry  # noqa: E402

RULE = "-" * 78


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)

    _status("loading corpus indexes (first run builds them, ~1 min)...", args)
    try:
        result = pipeline.process_log_sample(
            args.sample,
            limit=args.limit,
            top=args.top,
            min_confidence=args.min_confidence,
            log_rate_per_day=args.log_rate,
            taxonomy=_taxonomy_entries(),
            sigma_corpus=args.sigma_corpus,
            integrations_corpus=args.integrations,
            rebuild_index=args.rebuild_index,
            runbook_dir=args.runbook_dir,
            generate_runbooks=not args.no_runbooks,
        )
    except ingestion.ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    markdown = rejection_report.render_markdown(result.rejection) if result.rejection else None
    if markdown and args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(markdown, encoding="utf-8")

    if args.json:
        print(json.dumps(_json_payload(result), indent=2, ensure_ascii=False))
        return 0

    _report_sample(result)
    _report_fingerprint(result)
    _report_fields(result)
    _report_ecs_gap(result)
    _report_candidates(result, args.top)
    _report_runbooks(result, args)
    if markdown:
        print()
        print(RULE)
        print("REJECTION REPORT (hypothesis module)")
        print(RULE)
        print()
        print(markdown)
        if args.out:
            print(f"written to {args.out}")
    return 0


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    arg_parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    arg_parser.add_argument("sample", help="path to the raw log sample (CSV / JSON / JSONL)")
    arg_parser.add_argument("--limit", type=int, default=None, help="read at most N records")
    arg_parser.add_argument("--top", type=int, default=10, help="show at most N match candidates (default 10)")
    arg_parser.add_argument(
        "--min-confidence", type=float, default=pipeline.DEFAULT_MIN_CONFIDENCE,
        help="drop candidates below this confidence (default 0.4)",
    )
    arg_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON instead of a report")
    arg_parser.add_argument("--out", default=None, help="write the rejection report markdown to this path")
    arg_parser.add_argument("--runbook-dir", default=None, help="write a runbook per shown candidate into this directory")
    arg_parser.add_argument("--no-runbooks", action="store_true", help="skip runbook generation")
    arg_parser.add_argument(
        "--log-rate", type=float, default=None,
        help="expected production volume in events/day; without it, alert volume is extrapolated "
             "from the sample's own time span, which is unreliable for short samples",
    )
    arg_parser.add_argument("--rebuild-index", action="store_true", help="rebuild the cached corpus indexes")
    arg_parser.add_argument("--sigma-corpus", default=None, help="path to the Sigma rules directory")
    arg_parser.add_argument("--integrations", default=None, help="path to the elastic/integrations clone")
    return arg_parser.parse_args(argv)


def _status(message: str, args: argparse.Namespace) -> None:
    if not args.json:
        print(f"  ... {message}", file=sys.stderr)


def _taxonomy_entries() -> list[TaxonomyEntry]:
    """Load the internal taxonomy, if the database has been created."""
    try:
        from engine.storage import db, taxonomy_store

        if not db.DEFAULT_DB_PATH.exists():
            return []
        with db.connection() as conn:
            return taxonomy_store.list_entries(conn)
    except Exception as exc:  # noqa: BLE001 - report, but never block matching
        print(f"  ... internal taxonomy unavailable ({exc})", file=sys.stderr)
        return []


# ------------------------------------------------------------------ rendering


def _report_sample(result: PipelineResult) -> None:
    sample = result.sample
    print(RULE)
    print(f"SAMPLE  {sample.path}")
    print(RULE)
    detail = f"format {sample.format} | encoding {sample.encoding}"
    if sample.delimiter:
        detail += f" | delimiter {sample.delimiter!r}"
    print(f"  {detail}")
    print(f"  {sample.record_count} records, {sample.field_count} fields"
          + (" (truncated by --limit)" if sample.truncated else ""))
    if sample.decoded_records:
        print(f"  {sample.decoded_records} record(s) had URL-encoded values decoded at ingestion")
    for problem in sample.problems:
        print(f"  ! {problem}")


def _report_fingerprint(result: PipelineResult) -> None:
    fingerprint = result.fingerprint
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

    intel_entities = rule_type_classifier.intel_matchable_entities(fingerprint)
    if intel_entities:
        print(f"  intel-matchable  {', '.join(entity.value for entity in intel_entities)}"
              " -> an Indicator Match rule is possible against this sample")


def _report_fields(result: PipelineResult) -> None:
    print()
    print(RULE)
    print("FIELD PROFILE")
    print(RULE)
    print(f"  {'field':<26} {'type':<10} {'card':>5} {'null':>6}  {'entity':<13} ecs")
    print(f"  {'-' * 26} {'-' * 10} {'-' * 5} {'-' * 6}  {'-' * 13} {'-' * 24}")
    for profile in result.fingerprint.profiles:
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


def _report_ecs_gap(result: PipelineResult) -> None:
    gap = result.ecs_gap
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
        for index, line in enumerate(textwrap.wrap(note, width=96)):
            print(f"  note: {line}" if index == 0 else f"        {line}")


def _report_candidates(result: PipelineResult, top: int) -> None:
    print()
    print(RULE)
    print("MATCH CANDIDATES")
    print(RULE)

    corpus = f"{result.sigma_corpus_rules} Sigma rules" if result.sigma_corpus_available else "Sigma corpus NOT FOUND"
    print(f"  searched: {corpus}, {result.taxonomy_entries} internal taxonomy entr(ies)")
    if not result.sigma_corpus_available:
        print("  Run scripts\\setup.ps1 to clone the Sigma corpus.")

    if not result.candidates:
        print()
        print("  NO MATCH. The hypothesis module's rejection report follows.")
        return

    from_sigma = sum(1 for candidate in result.candidates if candidate.source.value == "sigma")
    print(f"  {len(result.candidates)} candidate(s) above the confidence floor "
          f"({from_sigma} sigma, {len(result.candidates) - from_sigma} internal); "
          f"showing {min(top, len(result.candidates))}")

    for position, candidate in enumerate(result.candidates[:top], start=1):
        decision = result.rule_types.get(candidate.rule_ref)
        forecast = result.predictions.get(candidate.rule_ref)
        print()
        print(f"  {position:>2}. [{candidate.confidence:.2f}] {candidate.title}")
        print(f"      {candidate.rule_ref}   source={candidate.source.value}"
              + (f"   level={candidate.level}" if candidate.level else ""))
        if candidate.rule_path:
            print(f"      {candidate.rule_path}")
        if candidate.mitre_techniques:
            print(f"      mitre: {', '.join(candidate.mitre_techniques)}")
        if decision:
            line = f"      rule type: {decision.elastic_type.value}"
            if decision.alternatives:
                line += f"   (also possible: {', '.join(t.value for t in decision.alternatives)})"
            print(line)
            print(f"        why: {decision.reasoning}")
            for caveat in decision.caveats:
                print(f"        caveat: {caveat}")
        print(f"      match: {candidate.reasoning}")
        for assumption in candidate.assumptions:
            print(f"        assumes: {assumption}")

        if forecast:
            backtest = forecast.backtest
            if backtest.evaluated:
                headline = (
                    f"      backtest: {backtest.matched_events}/{backtest.total_events} events match "
                    f"({backtest.match_rate:.1%})"
                )
                if backtest.alerts != backtest.matched_events:
                    headline += f", {backtest.alerts} alert(s) after aggregation"
                if forecast.projection_basis != "not projectable":
                    headline += f"  ->  ~{forecast.estimated_alert_volume:,.1f} alerts/day"
                print(headline + f"   [tier: {forecast.confidence_tier.value}]")
            else:
                print(f"      backtest: not run   [tier: {forecast.confidence_tier.value}]")
            for line in textwrap.wrap(forecast.notes, width=98):
                print(f"        {line}")


def _report_runbooks(result: PipelineResult, args: argparse.Namespace) -> None:
    if not result.runbooks:
        return

    print()
    print(RULE)
    print("RUNBOOKS")
    print(RULE)
    if args.runbook_dir:
        print(f"  {len(result.runbooks)} draft runbook(s) written to {args.runbook_dir}")
        for runbook in result.runbooks:
            print(f"    {Path(runbook.markdown_path).name}")
    else:
        print(f"  {len(result.runbooks)} draft runbook(s) generated in memory "
              "(pass --runbook-dir DIR to write them)")
        for runbook in result.runbooks[:3]:
            print(f"    {runbook.rule_name}  ({len(runbook.markdown):,} chars, "
                  f"{runbook.rule_type.elastic_type.value})")
    print()
    print("  Every runbook is a draft ending at a review checklist. Nothing is created in Kibana.")


def _json_payload(result: PipelineResult) -> dict:
    payload = result.model_dump(mode="json", exclude={"runbooks"})
    payload["runbooks"] = [
        {
            "rule_name": runbook.rule_name,
            "objective": runbook.objective,
            "mitre_mapping": runbook.mitre_mapping,
            "rule_type": runbook.rule_type.elastic_type.value,
            "markdown_path": runbook.markdown_path,
            "markdown": runbook.markdown,
        }
        for runbook in result.runbooks
    ]
    return payload


def _clip(text: str, width: int) -> str:
    # ASCII only: this prints to a Windows console whose code page may not be UTF-8.
    return text if len(text) <= width else text[: width - 3] + "..."


if __name__ == "__main__":
    raise SystemExit(main())
