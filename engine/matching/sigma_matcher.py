"""Match a LogFingerprint against the local Sigma corpus (docs/BLUEPRINT.md 5.3a).

Two questions decide whether a Sigma rule is a candidate:

1. **Does the logsource fit?** A rule that pins ``product: windows`` is not a
   candidate for a Cloudflare sample. A rule that only pins ``category: webserver``
   is, and matches more loosely.
2. **Are the fields it needs actually in the sample?** Sigma rules are written
   against a taxonomy (``cs-method``, ``sc-status``), not against vendor field
   names, so availability is checked through ECS: the sample's ``ClientRequestMethod``
   maps to ``http.request.method``, which is what ``cs-method`` means. This is the
   Phase 0 hand trace, automated.

Parsing the corpus with pySigma takes ~23s for 3144 rules, which is too slow to
repeat per run, so the parse result is reduced to an index and cached in
`data/sigma-index.json`, rebuilt only when the corpus changes.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, Sequence

from pydantic import BaseModel, Field

from engine.matching.candidate import MatchCandidate, MatchSource
from engine.profiling.field_profiler import LogFingerprint
from engine.storage.db import REPO_ROOT

DEFAULT_CORPUS_PATH = REPO_ROOT / "data" / "sigma-corpus" / "rules"
DEFAULT_CACHE_PATH = REPO_ROOT / "data" / "sigma-index.json"

_ATTACK_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

# Sigma's taxonomy field names, mapped to the ECS fields that mean the same
# thing. This is the same bridge pySigma's own ECS pipelines provide for the
# Windows taxonomy; the webserver/proxy half is what our log sources need.
SIGMA_TO_ECS: dict[str, str] = {
    # webserver / proxy access log taxonomy
    "c-ip": "source.ip",
    "c-uri": "url.original",
    "c-uri-extension": "url.extension",
    "c-uri-query": "url.query",
    "c-uri-stem": "url.path",
    "c-useragent": "user_agent.original",
    "cs-bytes": "http.request.bytes",
    "cs-cookie": "http.request.cookie",
    "cs-host": "url.domain",
    "cs-method": "http.request.method",
    "cs-referer": "http.request.referrer",
    "cs-referrer": "http.request.referrer",
    "cs-uri": "url.original",
    "cs-uri-query": "url.query",
    "cs-uri-stem": "url.path",
    "cs-user-agent": "user_agent.original",
    "cs-username": "user.name",
    "r-dns": "url.domain",
    "sc-bytes": "http.response.bytes",
    "sc-status": "http.response.status_code",
    "s-ip": "destination.ip",
    "s-port": "destination.port",
    # generic names used by firewall / network rules
    "src_ip": "source.ip",
    "dst_ip": "destination.ip",
    "src_port": "source.port",
    "dst_port": "destination.port",
    "destination.port": "destination.port",
    # dns taxonomy
    "query": "dns.question.name",
    "record_type": "dns.question.type",
    "answer": "dns.answers.data",
    "parent_domain": "dns.question.registered_domain",
}


class SigmaRuleEntry(BaseModel):
    """The parts of a Sigma rule that feasibility matching needs."""

    id: str | None = None
    title: str
    path: str
    category: str | None = None
    product: str | None = None
    service: str | None = None
    level: str | None = None
    status: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    detection_fields: list[str] = Field(default_factory=list)
    # An unnamed detection block is a full-text search over the whole event, so
    # it needs no specific field to be present.
    has_keywords: bool = False

    @property
    def reference(self) -> str:
        return f"sigma:{self.id}" if self.id else f"sigma:{Path(self.path).name}"


class SigmaRuleIndex(BaseModel):
    corpus_path: str
    fingerprint: str
    rules: list[SigmaRuleEntry] = Field(default_factory=list)
    parse_errors: int = 0


def load_rule_index(
    corpus_path: str | Path | None = None,
    *,
    cache_path: str | Path | None = None,
    rebuild: bool = False,
) -> SigmaRuleIndex | None:
    """Return the Sigma rule index, building and caching it when stale.

    Returns None when the corpus is missing, so the caller can say so rather
    than report "no matches" for what is really "nothing to match against".
    """
    corpus = Path(corpus_path) if corpus_path else DEFAULT_CORPUS_PATH
    cache = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH

    if not corpus.is_dir():
        return None

    fingerprint = _corpus_fingerprint(corpus)
    if not rebuild and cache.exists():
        try:
            cached = SigmaRuleIndex.model_validate_json(cache.read_text(encoding="utf-8"))
            if cached.fingerprint == fingerprint:
                return cached
        except Exception:  # noqa: BLE001 - a corrupt cache is a rebuild, not a crash
            pass

    index = build_rule_index(corpus, fingerprint=fingerprint)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(index.model_dump_json(), encoding="utf-8")
    return index


def build_rule_index(corpus_path: str | Path, *, fingerprint: str | None = None) -> SigmaRuleIndex:
    """Parse the corpus with pySigma and reduce it to the matchable essentials."""
    from sigma.collection import SigmaCollection  # imported lazily: ~1s of import cost

    corpus = Path(corpus_path)
    collection = SigmaCollection.load_ruleset([corpus], collect_errors=True)

    entries: list[SigmaRuleEntry] = []
    for rule in collection.rules:
        logsource = getattr(rule, "logsource", None)
        if logsource is None:  # correlation rules carry no logsource of their own
            continue
        fields, has_keywords = _detection_fields(rule)
        entries.append(
            SigmaRuleEntry(
                id=str(rule.id) if rule.id else None,
                title=rule.title,
                path=_relative_path(rule, corpus),
                category=logsource.category,
                product=logsource.product,
                service=logsource.service,
                level=str(rule.level) if rule.level else None,
                status=str(rule.status) if rule.status else None,
                mitre_techniques=_mitre_techniques(rule),
                detection_fields=sorted(fields),
                has_keywords=has_keywords,
            )
        )

    return SigmaRuleIndex(
        corpus_path=str(corpus),
        fingerprint=fingerprint or _corpus_fingerprint(corpus),
        rules=entries,
        parse_errors=len(collection.errors),
    )


def load_rule(index: SigmaRuleIndex, relative_path: str) -> object | None:
    """Re-parse one rule file, for the backtester that needs its full logic.

    The index deliberately keeps only what matching needs, so the detection tree
    is read back on demand. Parsing a handful of files costs milliseconds; keeping
    every parsed rule in the cache would not.
    """
    if not relative_path:
        return None

    from sigma.rule import SigmaRule  # imported lazily, like the ruleset loader

    path = Path(index.corpus_path).parent / relative_path
    if not path.is_file():
        return None
    try:
        return SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - an unparsable rule is reported, not fatal
        return None


def _detection_fields(rule) -> tuple[set[str], bool]:
    fields: set[str] = set()
    has_keywords = False
    for detection in rule.detection.detections.values():
        for item in _walk_detection(detection):
            field = getattr(item, "field", None)
            if field is None:
                has_keywords = True
            else:
                fields.add(field)
    return fields, has_keywords


def _walk_detection(detection) -> Iterator[object]:
    """Yield leaf detection items, descending through nested detections.

    Duck-typed on ``detection_items`` rather than isinstance, so a pySigma
    refactor of the class layout does not silently drop fields here.
    """
    for item in getattr(detection, "detection_items", ()):
        if hasattr(item, "detection_items"):
            yield from _walk_detection(item)
        else:
            yield item


def _mitre_techniques(rule) -> list[str]:
    techniques: list[str] = []
    for tag in getattr(rule, "tags", ()):
        match = _ATTACK_TECHNIQUE_RE.match(str(tag))
        if match:
            techniques.append(match.group(1).upper())
    return sorted(set(techniques))


def _relative_path(rule, corpus: Path) -> str:
    source = getattr(rule, "source", None)
    path = getattr(source, "path", None)
    if path is None:
        return ""
    try:
        return str(Path(path).relative_to(corpus.parent))
    except ValueError:
        return str(path)


def _corpus_fingerprint(corpus: Path) -> str:
    newest = 0.0
    count = 0
    for path in corpus.rglob("*.yml"):
        count += 1
        try:
            newest = max(newest, path.stat().st_mtime)
        except OSError:
            continue
    return f"{count}:{newest:.0f}"


# ------------------------------------------------------------------- matching


def match(
    fingerprint: LogFingerprint,
    index: SigmaRuleIndex,
    *,
    min_confidence: float = 0.0,
    limit: int | None = None,
) -> list[MatchCandidate]:
    """Return the Sigma rules this sample could support, best first."""
    available = fingerprint.resolvable_names()

    candidates: list[MatchCandidate] = []
    for rule in index.rules:
        logsource_score = _logsource_score(rule, fingerprint)
        if logsource_score is None:
            continue

        matched, missing = _field_availability(rule.detection_fields, available)
        total_required = len(matched) + len(missing)
        coverage = 1.0 if total_required == 0 else len(matched) / total_required

        # A rule that needs a field the sample does not have is not feasible as
        # written; keep it only if something is still satisfiable, so the report
        # can say what is missing instead of hiding the near-misses.
        if total_required and not matched and not rule.has_keywords:
            continue

        # Coverage alone ties every satisfiable webserver rule at the same score,
        # which is useless for triage. The third term breaks that tie by how much
        # of the rule is verifiably supported: a rule whose four fields are all
        # present is better evidenced than one resting on a single field.
        specificity = min(len(matched), 4) / 4
        confidence = 0.45 * logsource_score + 0.45 * coverage + 0.10 * specificity
        if total_required == 0 and rule.has_keywords:
            # Feasible against any log, but says little about this one.
            confidence *= 0.85

        if confidence < min_confidence:
            continue

        candidates.append(
            MatchCandidate(
                source=MatchSource.SIGMA,
                rule_ref=rule.reference,
                confidence=round(confidence, 3),
                mitre_techniques=rule.mitre_techniques,
                title=rule.title,
                level=rule.level,
                rule_path=rule.path,
                logsource={"category": rule.category, "product": rule.product, "service": rule.service},
                matched_fields=matched,
                missing_fields=missing,
                uses_full_text_search=rule.has_keywords,
                reasoning=_reasoning(rule, fingerprint, matched, missing, coverage),
            )
        )

    candidates.sort(key=lambda candidate: (-candidate.confidence, candidate.title))
    return candidates[:limit] if limit else candidates


def _field_availability(
    required: Sequence[str],
    available: dict[str, str],
) -> tuple[dict[str, str], list[str]]:
    matched: dict[str, str] = {}
    missing: list[str] = []

    for field in required:
        lowered = field.lower()
        provider = available.get(lowered)
        if provider is None:
            ecs_equivalent = SIGMA_TO_ECS.get(lowered)
            if ecs_equivalent:
                provider = available.get(ecs_equivalent.lower())
        if provider is None and "." in lowered:
            provider = available.get(lowered.rsplit(".", 1)[-1])
        if provider is None:
            missing.append(field)
        else:
            matched[field] = provider

    return matched, missing


def _logsource_score(rule: SigmaRuleEntry, fingerprint: LogFingerprint) -> float | None:
    """Score the logsource fit, or None when the rule is for a different source.

    A rule element that the fingerprint cannot confirm is treated as a mismatch.
    Guessing the other way would hand the analyst Windows rules for a firewall log.
    """
    specified = 0
    confirmed = 0
    for rule_value, sample_value in (
        (rule.category, fingerprint.inferred_category),
        (rule.product, fingerprint.inferred_product),
        (rule.service, fingerprint.inferred_service),
    ):
        if rule_value is None:
            continue
        specified += 1
        if sample_value is None or rule_value.lower() != sample_value.lower():
            return None
        confirmed += 1

    if specified == 0:
        # Applies to everything, so it distinguishes nothing.
        return 0.3
    return {1: 0.6, 2: 0.85, 3: 1.0}[confirmed]


def _reasoning(
    rule: SigmaRuleEntry,
    fingerprint: LogFingerprint,
    matched: dict[str, str],
    missing: Sequence[str],
    coverage: float,
) -> str:
    parts: list[str] = []

    pinned = [
        f"{element}={value}"
        for element, value in (("category", rule.category), ("product", rule.product), ("service", rule.service))
        if value
    ]
    if pinned:
        parts.append("logsource " + ", ".join(pinned) + " matches the fingerprint")
    else:
        parts.append("rule pins no logsource, so it applies to any log")

    if matched:
        shown = ", ".join(f"{sigma_field} <- {sample_field}" for sigma_field, sample_field in list(matched.items())[:4])
        suffix = ", ..." if len(matched) > 4 else ""
        parts.append(f"fields available: {shown}{suffix}")
    if missing:
        parts.append(f"fields missing: {', '.join(missing)} ({coverage:.0%} coverage)")
    if rule.has_keywords:
        parts.append("rule also does a full-text keyword search, which needs no specific field")
    if fingerprint.official_integration_name:
        parts.append(f"field mapping via {fingerprint.official_integration_name}")

    return "; ".join(parts)
