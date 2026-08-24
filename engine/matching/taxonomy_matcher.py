"""Match a LogFingerprint against the internal taxonomy (docs/BLUEPRINT.md 5.3b).

This is the half of matching that Sigma does not reach: proprietary applications,
custom APIs, niche vendors, and the vendor-specific detail public rules cannot
encode. Entries are written by analysts out of real project work and grow one
project at a time.

It runs in parallel with the Sigma matcher, not as a fallback. A sample can be
covered by both, and often the taxonomy entry is the better candidate: on the
Phase 0 fixture the internal SQL injection entry caught 5 of 5 attempts against
the Sigma rule's 2, because it reads Cloudflare's own WAF verdict instead of
guessing from payload text.

Unlike a Sigma rule, a taxonomy entry carries a curated confidence. That value
is treated as a ceiling: a perfect structural match cannot score higher than the
analyst who wrote the entry was willing to claim.
"""

from __future__ import annotations

from typing import Sequence

from engine.matching.candidate import MatchCandidate, MatchSource
from engine.profiling.field_profiler import LogFingerprint
from engine.storage.taxonomy_store import TaxonomyEntry


def match(
    fingerprint: LogFingerprint,
    entries: Sequence[TaxonomyEntry],
    *,
    min_confidence: float = 0.0,
    limit: int | None = None,
) -> list[MatchCandidate]:
    """Return the taxonomy entries this sample could support, best first."""
    available = fingerprint.resolvable_names()

    candidates: list[MatchCandidate] = []
    for entry in entries:
        logsource_score = _logsource_score(entry, fingerprint)
        if logsource_score is None:
            continue

        matched, missing = _field_availability(entry.required_fields, available)
        total = len(matched) + len(missing)
        coverage = 1.0 if total == 0 else len(matched) / total
        if total and not matched:
            continue

        # The curator's confidence caps the result; structural fit scales it down.
        structural = 0.5 * logsource_score + 0.5 * coverage
        confidence = entry.confidence * structural
        if confidence < min_confidence:
            continue

        candidates.append(
            MatchCandidate(
                source=MatchSource.INTERNAL_TAXONOMY,
                rule_ref=f"internal:{entry.slug}",
                confidence=round(confidence, 3),
                mitre_techniques=list(entry.mitre_techniques),
                title=entry.name,
                level=None,
                rule_path=None,
                logsource={
                    "category": entry.logsource_category,
                    "product": entry.logsource_product,
                    "service": entry.logsource_service,
                },
                matched_fields=matched,
                missing_fields=missing,
                uses_full_text_search=False,
                assumptions=list(entry.assumptions),
                reasoning=_reasoning(entry, matched, missing, coverage),
            )
        )

    candidates.sort(key=lambda candidate: (-candidate.confidence, candidate.title))
    return candidates[:limit] if limit else candidates


def _logsource_score(entry: TaxonomyEntry, fingerprint: LogFingerprint) -> float | None:
    """Score the logsource fit, or None when the entry is for a different source.

    Same rule as the Sigma matcher: an element the fingerprint cannot confirm is
    a mismatch, not a maybe. The data category is checked only for contradiction,
    because it is a coarser signal than the logsource triple and an unknown one
    should not veto an otherwise exact match.
    """
    specified = 0
    for entry_value, sample_value in (
        (entry.logsource_category, fingerprint.inferred_category),
        (entry.logsource_product, fingerprint.inferred_product),
        (entry.logsource_service, fingerprint.inferred_service),
    ):
        if entry_value is None:
            continue
        specified += 1
        if sample_value is None or entry_value.lower() != sample_value.lower():
            return None

    if (
        entry.data_category
        and fingerprint.data_category
        and entry.data_category.lower() != fingerprint.data_category.value.lower()
    ):
        return None

    if specified == 0:
        return 0.3
    return {1: 0.6, 2: 0.85, 3: 1.0}[specified]


def _field_availability(
    required: Sequence[str],
    available: dict[str, str],
) -> tuple[dict[str, str], list[str]]:
    matched: dict[str, str] = {}
    missing: list[str] = []

    for field in required:
        lowered = field.lower()
        provider = available.get(lowered)
        if provider is None and "." in lowered:
            provider = available.get(lowered.rsplit(".", 1)[-1])
        if provider is None:
            missing.append(field)
        else:
            matched[field] = provider

    return matched, missing


def _reasoning(
    entry: TaxonomyEntry,
    matched: dict[str, str],
    missing: Sequence[str],
    coverage: float,
) -> str:
    parts: list[str] = []

    pinned = [
        f"{element}={value}"
        for element, value in (
            ("category", entry.logsource_category),
            ("product", entry.logsource_product),
            ("service", entry.logsource_service),
        )
        if value
    ]
    if pinned:
        parts.append("internal taxonomy entry for " + ", ".join(pinned))
    else:
        parts.append("internal taxonomy entry with no logsource constraint")

    parts.append(f"curator confidence {entry.confidence}")

    if missing:
        parts.append(
            f"NOT feasible as written: required field(s) absent - {', '.join(missing)} "
            f"({coverage:.0%} of required fields present)"
        )
    elif matched:
        parts.append(f"all {len(matched)} required field(s) present")

    if entry.assumptions:
        # Listed in full on the candidate itself; only counted here so the
        # one-line reasoning stays readable.
        parts.append(f"{len(entry.assumptions)} documented assumption(s)")
    if entry.source_project:
        parts.append(f"from {entry.source_project}")

    return "; ".join(parts)
