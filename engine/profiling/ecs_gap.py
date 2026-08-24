"""ECS gap analysis against the local elastic/integrations clone (BLUEPRINT 5.2).

The order the blueprint asks for: before inventing a custom mapping, check
whether the vendor already has an official Elastic integration, because pointing
an implementation at a maintained ingest pipeline beats hand-rolling one.

**Resolution is by data stream fields, never by vendor name.** Phase 0 found
that `cloudflare` and `cloudflare_logpush` are both "Cloudflare", and only the
latter has a `firewall_event` data stream matching the sample's shape; a
vendor-name lookup picks the wrong package. See docs/phase0-smoke-test.md §9.

The index is built by reading the ingest pipelines in the clone: a `rename` from
a source field to a target, plus the `set ... copy_from` chains that follow, is
the vendor-to-ECS mapping stated by Elastic itself. Building it takes a few
seconds over ~500 packages, so the result is cached in `data/integration-index.json`
and rebuilt only when the clone changes.

Known limit: packages whose pipelines parse syslog with grok expose their source
field names inside grok patterns rather than as `rename` sources, so such data
streams are indexed only by the names their renames do mention.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

import yaml
from pydantic import BaseModel, Field

from engine.profiling.entity_recognition import EntityType
from engine.profiling.field_profiler import FieldProfile
from engine.storage.db import REPO_ROOT

DEFAULT_CORPUS_PATH = REPO_ROOT / "data" / "elastic-integrations"
DEFAULT_CACHE_PATH = REPO_ROOT / "data" / "integration-index.json"

# Part of the cache key. Bump it whenever the indexer's output changes shape or
# meaning, otherwise a cache written by an older build stays valid forever: the
# corpus files have not changed, so the file-count-and-mtime key still matches
# and the stale index is reused with no sign anything is wrong.
INDEX_SCHEMA_VERSION = 2

# A field is considered ECS-shaped when its first dotted segment is one of these.
# Taken from the ECS top-level field sets.
ECS_ROOTS = frozenset({
    "agent", "as", "client", "cloud", "code_signature", "container", "data_stream",
    "destination", "device", "dll", "dns", "ecs", "elf", "email", "error", "event",
    "faas", "file", "geo", "group", "hash", "host", "http", "interface", "log",
    "macho", "network", "observer", "orchestrator", "organization", "package", "pe",
    "process", "registry", "related", "risk", "rule", "server", "service", "source",
    "span", "threat", "tls", "trace", "transaction", "url", "user", "user_agent",
    "volume", "vulnerability", "x509",
})
ECS_SCALARS = frozenset({"@timestamp", "message", "tags", "labels"})

# Staging prefixes elastic/integrations pipelines park unparsed input under.
_STAGING_PREFIXES = ("json.", "_temp_.", "_tmp.", "aws.cloudwatch.")

# Processors that write to a well-known ECS target when `target_field` is
# omitted. Without these, every field an integration maps through a date or
# user_agent processor would look unmapped.
_DEFAULT_TARGETS = {
    "date": "@timestamp",
    # Both processors write an object, but the leaf that holds the original
    # string is what a detection rule actually reads, and naming the object
    # would leave a rule looking for `user_agent.original` reported as missing.
    "uri_parts": "url.original",
    "user_agent": "user_agent.original",
}

_MIN_MATCHED_FIELDS = 3
_MIN_COVERAGE = 0.25
# How close to the best score still counts as a tie for the product-name check.
_TIE_BREAK_MARGIN = 0.9
# A field carried by more than this share of all data streams says nothing about
# which integration a sample belongs to. `host`, `timestamp`, and `severity` are
# in almost every package; matching on them alone once resolved a 4-field
# appliance syslog to an OSINT scanning tool.
_DISTINCTIVE_DF_RATIO = 0.05
_MIN_DISTINCTIVE_FIELDS = 2

# Unambiguous ops fields, for samples no integration covers. Value-based entity
# recognition cannot label these: a syslog severity is just a short string, and
# a hostname like `vpn-gw-01` is not an FQDN.
_NAME_TO_ECS: dict[str, str] = {
    "severity": "log.level",
    "level": "log.level",
    "loglevel": "log.level",
    "log_level": "log.level",
    "message": "message",
    "msg": "message",
    "host": "host.name",
    "hostname": "host.name",
    "computer": "host.name",
    "devname": "observer.name",
    "facility": "log.syslog.facility.name",
}

# Fallback suggestions when no official integration covers the field. Keyed by
# entity type, refined by what the field name says about direction.
_SOURCE_HINTS = ("src", "source", "client", "orig", "sender", "from")
_DESTINATION_HINTS = ("dst", "dest", "destination", "server", "resp", "target", "to")
_HOST_NAMES = re.compile(r"(computer|hostname|host$|machine|workstation|devname|nodename)", re.IGNORECASE)
_TIME_NAMES = re.compile(r"(time|date|timestamp|created|received|@timestamp)", re.IGNORECASE)


class DataStreamProfile(BaseModel):
    """One integration data stream, as far as field mapping is concerned."""

    package: str
    data_stream: str
    title: str | None = None
    # Lowercased candidate source names: the full staged name and its last
    # dotted segment, so `fortinet.firewall.srcip` also answers to `srcip`.
    source_fields: list[str] = Field(default_factory=list)
    ecs_mappings: dict[str, str] = Field(default_factory=dict)

    @property
    def name(self) -> str:
        return f"{self.package} / {self.data_stream}"


class IntegrationIndex(BaseModel):
    corpus_path: str
    fingerprint: str
    pipeline_files: int
    parse_failures: int = 0
    data_streams: list[DataStreamProfile] = Field(default_factory=list)
    ecs_fields: list[str] = Field(default_factory=list)
    # How many data streams carry each source field name. A name in hundreds of
    # them carries no evidence about which integration a sample belongs to.
    field_document_frequency: dict[str, int] = Field(default_factory=dict)

    def is_distinctive(self, field_name: str) -> bool:
        limit = max(1, int(len(self.data_streams) * _DISTINCTIVE_DF_RATIO))
        return self.field_document_frequency.get(field_name, 0) <= limit


class IntegrationMatch(BaseModel):
    package: str
    data_stream: str
    title: str | None = None
    matched_fields: list[str] = Field(default_factory=list)
    coverage: float = 0.0
    ecs_mappings: dict[str, str] = Field(default_factory=dict)

    @property
    def name(self) -> str:
        return f"{self.package} / {self.data_stream}"


class EcsGapReport(BaseModel):
    """Per-sample ECS position: what is already ECS, what maps, what does not."""

    integration: IntegrationMatch | None = None
    compliant_fields: list[str] = Field(default_factory=list)
    mapped_fields: dict[str, str] = Field(default_factory=dict)
    suggested_fields: dict[str, str] = Field(default_factory=dict)
    unmapped_fields: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------- index


def load_index(
    corpus_path: str | Path | None = None,
    *,
    cache_path: str | Path | None = None,
    rebuild: bool = False,
) -> IntegrationIndex | None:
    """Return the integration index, building and caching it when stale.

    Returns None when the corpus has not been cloned, so callers can degrade to
    heuristic mapping rather than fail.
    """
    corpus = Path(corpus_path) if corpus_path else DEFAULT_CORPUS_PATH
    cache = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH

    if not (corpus / "packages").is_dir():
        return None

    fingerprint = _corpus_fingerprint(corpus)
    if not rebuild and cache.exists():
        try:
            cached = IntegrationIndex.model_validate_json(cache.read_text(encoding="utf-8"))
            if cached.fingerprint == fingerprint:
                return cached
        except Exception:  # noqa: BLE001 - a corrupt cache is a rebuild, not a crash
            pass

    index = build_index(corpus, fingerprint=fingerprint)
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(index.model_dump_json(), encoding="utf-8")
    return index


def build_index(corpus_path: str | Path, *, fingerprint: str | None = None) -> IntegrationIndex:
    """Parse every ingest pipeline in the clone into a field-mapping index."""
    corpus = Path(corpus_path)
    packages_dir = corpus / "packages"
    titles = _package_titles(packages_dir)

    data_streams: list[DataStreamProfile] = []
    ecs_fields: set[str] = set(ECS_SCALARS)
    pipeline_files = 0
    parse_failures = 0

    for pipeline_dir in sorted(packages_dir.glob("*/data_stream/*/elasticsearch/ingest_pipeline")):
        data_stream_dir = pipeline_dir.parent.parent
        package = data_stream_dir.parent.parent.name
        data_stream = data_stream_dir.name

        sources: set[str] = set()
        edges: dict[str, str] = {}
        copies: list[tuple[str, str]] = []

        for pipeline_file in sorted(pipeline_dir.glob("*.yml")):
            pipeline_files += 1
            try:
                document = yaml.safe_load(pipeline_file.read_text(encoding="utf-8"))
            except (yaml.YAMLError, UnicodeDecodeError, OSError):
                parse_failures += 1
                continue
            _collect_from_pipeline(document, sources, edges, copies)

        mappings = _resolve_mappings(edges, copies)
        ecs_fields.update(target for target in mappings.values())
        ecs_fields.update(target for _, target in copies if _is_ecs_shaped(target))

        if sources or mappings:
            data_streams.append(
                DataStreamProfile(
                    package=package,
                    data_stream=data_stream,
                    title=titles.get(package),
                    source_fields=sorted(sources),
                    ecs_mappings=mappings,
                )
            )

    document_frequency: dict[str, int] = {}
    for profile in data_streams:
        for source_field in profile.source_fields:
            document_frequency[source_field] = document_frequency.get(source_field, 0) + 1

    return IntegrationIndex(
        corpus_path=str(corpus),
        fingerprint=fingerprint or _corpus_fingerprint(corpus),
        pipeline_files=pipeline_files,
        parse_failures=parse_failures,
        data_streams=data_streams,
        ecs_fields=sorted(field for field in ecs_fields if _is_ecs_shaped(field)),
        field_document_frequency=document_frequency,
    )


def _collect_from_pipeline(
    document: Any,
    sources: set[str],
    edges: dict[str, str],
    copies: list[tuple[str, str]],
) -> None:
    for processor_type, options in _iter_processors(document):
        field = options.get("field")
        target = options.get("target_field")
        copy_from = options.get("copy_from")

        if isinstance(field, str):
            for candidate in _source_candidates(field):
                sources.add(candidate)
            # Any processor that reads one field and writes another states a
            # mapping: `rename` for plain moves, but also `convert` for typed
            # ones (IPs, longs) and `date` for timestamps.
            effective = target if isinstance(target, str) else _DEFAULT_TARGETS.get(processor_type)
            if effective:
                _record_edge(edges, field, effective)

        if isinstance(copy_from, str):
            for candidate in _source_candidates(copy_from):
                sources.add(candidate)
            if isinstance(field, str):
                copies.append((copy_from, field))


def _record_edge(edges: dict[str, str], field: str, target: str) -> None:
    """Keep one target per source, preferring an ECS one over a vendor namespace."""
    existing = edges.get(field)
    if existing is None or (_is_ecs_shaped(target) and not _is_ecs_shaped(existing)):
        edges[field] = target


def _iter_processors(node: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    """Walk a pipeline document, including nested on_failure/foreach processors."""
    if isinstance(node, dict):
        for key in ("processors", "on_failure"):
            entries = node.get(key)
            if isinstance(entries, list):
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    for processor_type, options in entry.items():
                        if isinstance(options, dict):
                            yield processor_type, options
                            yield from _iter_processors(options)
        processor = node.get("processor")
        if isinstance(processor, dict):
            yield from _iter_processors({"processors": [processor]})


def _source_candidates(field: str) -> Iterable[str]:
    """Candidate raw names a sample column could be called, lowercased."""
    stripped = field
    for prefix in _STAGING_PREFIXES:
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
            break

    if not stripped or _is_ecs_shaped(stripped):
        return ()

    candidates = {stripped.lower()}
    if "." in stripped:
        candidates.add(stripped.rsplit(".", 1)[-1].lower())
    return candidates


def _resolve_mappings(edges: dict[str, str], copies: list[tuple[str, str]]) -> dict[str, str]:
    """Turn field-to-field edges and copy_from chains into raw-source -> ECS mappings.

    Pipelines usually move a vendor field into the package namespace and then
    copy that into ECS, e.g. `json.ClientIP` -> `cloudflare_logpush...client.ip`
    -> `source.ip`. Both hops are needed to state the real ECS target.
    """
    copy_targets: dict[str, list[str]] = {}
    for copy_from, target in copies:
        copy_targets.setdefault(copy_from, []).append(target)

    mappings: dict[str, str] = {}
    for source, target in edges.items():
        raw = _strip_staging(source)
        if not raw or _is_ecs_shaped(raw):
            continue
        if _is_ecs_shaped(target):
            mappings[raw] = target
            continue
        ecs_targets = [candidate for candidate in copy_targets.get(target, []) if _is_ecs_shaped(candidate)]
        if ecs_targets:
            mappings[raw] = _preferred_ecs_target(ecs_targets)

    # Direct `set field: url.domain copy_from: json.ClientRequestHost`.
    for copy_from, target in copies:
        raw = _strip_staging(copy_from)
        if raw and not _is_ecs_shaped(raw) and _is_ecs_shaped(target):
            mappings.setdefault(raw, target)

    return mappings


def _preferred_ecs_target(candidates: Sequence[str]) -> str:
    """Pick one ECS target deterministically.

    `related.*` is ECS's cross-reference index, a copy of a value that also lives
    somewhere more specific, so it loses to any other candidate.
    """
    return sorted(candidates, key=lambda field: (field.startswith("related."), field))[0]


def _strip_staging(field: str) -> str:
    for prefix in _STAGING_PREFIXES:
        if field.startswith(prefix):
            return field[len(prefix):]
    return field


def _is_ecs_shaped(field: str) -> bool:
    if field in ECS_SCALARS:
        return True
    root = field.split(".", 1)[0]
    return root in ECS_ROOTS


def _package_titles(packages_dir: Path) -> dict[str, str]:
    titles: dict[str, str] = {}
    for manifest in packages_dir.glob("*/manifest.yml"):
        try:
            document = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError, OSError):
            continue
        if isinstance(document, dict) and isinstance(document.get("title"), str):
            titles[manifest.parent.name] = document["title"]
    return titles


def _corpus_fingerprint(corpus: Path) -> str:
    """Cache key: the indexer's version, plus the corpus file count and newest mtime."""
    newest = 0.0
    count = 0
    for path in (corpus / "packages").glob("*/data_stream/*/elasticsearch/ingest_pipeline/*.yml"):
        count += 1
        try:
            newest = max(newest, path.stat().st_mtime)
        except OSError:
            continue
    return f"v{INDEX_SCHEMA_VERSION}:{count}:{newest:.0f}"


# -------------------------------------------------------------------- lookup


def find_integration(
    index: IntegrationIndex,
    field_names: Sequence[str],
    *,
    product_hint: str | None = None,
) -> IntegrationMatch | None:
    """Find the data stream whose source fields best explain this sample.

    Fields decide. ``product_hint`` only breaks ties, because vendors ship
    near-identical field sets across their own product line: FortiGate and
    FortiProxy logs share almost every name, and picking on field overlap alone
    is a coin flip between them.
    """
    wanted = {name.lower() for name in field_names if name}
    wanted |= {name.rsplit(".", 1)[-1].lower() for name in field_names if "." in name}
    if not wanted:
        return None

    scored: list[tuple[float, float, DataStreamProfile, set[str]]] = []
    for profile in index.data_streams:
        matched = wanted & set(profile.source_fields)
        if len(matched) < _MIN_MATCHED_FIELDS:
            continue
        # Generic names are not evidence. Without this, a sample of
        # timestamp/host/severity/message matches whichever package happens to
        # declare the most common fields.
        distinctive = [field for field in matched if index.is_distinctive(field)]
        if len(distinctive) < _MIN_DISTINCTIVE_FIELDS:
            continue
        scored.append((_overlap_score(matched, wanted, profile), len(matched) / len(wanted), profile, matched))

    if not scored:
        return None

    scored.sort(key=lambda entry: (-entry[0], -entry[1], entry[2].name))
    best = scored[0]

    if product_hint:
        # Anything within a short distance of the top is a near-tie; among those,
        # the vendor's own package wins.
        threshold = best[0] * _TIE_BREAK_MARGIN
        for entry in scored:
            if entry[0] < threshold:
                break
            if _package_matches_product(entry[2].package, product_hint):
                best = entry
                break

    if best[1] < _MIN_COVERAGE:
        return None

    _, coverage, profile, matched = best
    return IntegrationMatch(
        package=profile.package,
        data_stream=profile.data_stream,
        title=profile.title,
        matched_fields=sorted(matched),
        coverage=round(coverage, 3),
        ecs_mappings=profile.ecs_mappings,
    )


def _lookup_table(ecs_mappings: dict[str, str]) -> dict[str, str]:
    """Index an integration's mappings by both their full and short names.

    A pipeline states its mapping against the staged name it uses internally,
    e.g. `fortinet.firewall.srcip`, while the sample column is just `srcip`.
    Without the short alias every FortiGate field would look unmapped despite
    the integration mapping all of them.
    """
    table = {key.lower(): value for key, value in ecs_mappings.items()}
    for key, value in sorted(ecs_mappings.items()):
        if "." in key:
            table.setdefault(key.rsplit(".", 1)[-1].lower(), value)
    return table


def _overlap_score(matched: set[str], wanted: set[str], profile: DataStreamProfile) -> float:
    """Rank a data stream by an F2 score over the sample's fields.

    Counting matched fields alone rewards verbosity: FortiProxy declares 424
    source fields to FortiGate's 272, so it catches more of any Fortinet sample
    by sheer vocabulary size and wins a contest it should lose. Precision
    (how much of the data stream this sample actually uses) corrects that.
    Recall stays weighted higher, because a small data stream that happens to
    use three of our field names is not a better answer than a large one that
    explains two thirds of the sample.
    """
    recall = len(matched) / len(wanted)
    precision = len(matched) / max(len(profile.source_fields), 1)
    if precision + recall == 0:
        return 0.0
    return 5 * precision * recall / (4 * precision + recall)


def _package_matches_product(package: str, product: str) -> bool:
    left = re.sub(r"[^a-z0-9]", "", package.lower())
    right = re.sub(r"[^a-z0-9]", "", product.lower())
    if not left or not right:
        return False
    return left.startswith(right) or right.startswith(left)


def analyse(
    profiles: Sequence[FieldProfile],
    index: IntegrationIndex | None,
    *,
    match: IntegrationMatch | None = None,
    product_hint: str | None = None,
) -> EcsGapReport:
    """Fill in ECS status for every profile and report what stays unmapped.

    Updates ``is_ecs_compliant`` and ``suggested_ecs_field`` on the profiles in
    place, and returns the summary.
    """
    field_names = [profile.field_name for profile in profiles]
    if index is not None and match is None:
        match = find_integration(index, field_names, product_hint=product_hint)

    ecs_vocabulary = set(index.ecs_fields) if index else set()
    mappings = _lookup_table(match.ecs_mappings if match else {})

    report = EcsGapReport(integration=match)

    for profile in profiles:
        name = profile.field_name
        lowered = name.lower()

        if name in ecs_vocabulary or (not ecs_vocabulary and _is_ecs_shaped(name)):
            profile.is_ecs_compliant = True
            profile.suggested_ecs_field = None
            report.compliant_fields.append(name)
            continue

        profile.is_ecs_compliant = False
        official = mappings.get(lowered)
        if official is None and "." in lowered:
            official = mappings.get(lowered.rsplit(".", 1)[-1])
        if official:
            profile.suggested_ecs_field = official
            report.mapped_fields[name] = official
            continue

        suggestion = _heuristic_ecs_field(profile)
        profile.suggested_ecs_field = suggestion
        if suggestion:
            report.suggested_fields[name] = suggestion
        else:
            report.unmapped_fields.append(name)

    _add_notes(report, match, index)
    return report


def _add_notes(report: EcsGapReport, match: IntegrationMatch | None, index: IntegrationIndex | None) -> None:
    if index is None:
        report.notes.append(
            "elastic/integrations is not cloned locally, so no official integration could be "
            "checked; every suggestion below is heuristic. Run scripts\\setup.ps1."
        )
        return

    if match is None:
        report.notes.append(
            "No official integration data stream matches this field set. Treat the mapping "
            "suggestions as a starting point for a custom ingest pipeline, per BLUEPRINT 5.2 step 2."
        )
        return

    report.notes.append(
        f"Official integration available: {match.name}"
        + (f" ({match.title})" if match.title else "")
        + f", matching {len(match.matched_fields)} of the sample's fields "
        f"({match.coverage:.0%} coverage). Installing it is likely faster than a custom mapping."
    )
    if not match.ecs_mappings:
        report.notes.append(
            "That integration's pipeline parses its input with grok or kv rather than renaming "
            "named fields, so no ECS targets could be read out of it. The field mappings below "
            "are heuristic; confirm them against the integration's own field definitions."
        )
    elif report.suggested_fields or report.unmapped_fields:
        left_over = len(report.suggested_fields) + len(report.unmapped_fields)
        report.notes.append(
            f"{left_over} field(s) are not mapped to ECS by that integration; they stay in the "
            "vendor namespace. Any rule that depends on them needs the mapping added, or must "
            "read the vendor field directly."
        )


def _heuristic_ecs_field(profile: FieldProfile) -> str | None:
    """Suggest an ECS field from the entity type and what the name implies."""
    lowered = profile.field_name.lower()

    if profile.dtype == "timestamp" and _TIME_NAMES.search(lowered):
        return "@timestamp"

    entity = profile.entity_type
    if entity is None:
        return _NAME_TO_ECS.get(lowered)

    # Direction words only mean source/destination for network endpoints. For a
    # user, "target" is the account acted on, not a network peer, so
    # TargetUserName is user.name -- destination.user.name would be wrong.
    direction = None
    if any(hint in lowered for hint in _SOURCE_HINTS):
        direction = "source"
    elif any(hint in lowered for hint in _DESTINATION_HINTS):
        direction = "destination"

    if entity is EntityType.IP:
        return f"{direction}.ip" if direction else "related.ip"
    if entity is EntityType.PORT:
        return f"{direction}.port" if direction else "network.port"
    if entity is EntityType.USER:
        return "user.name"
    if entity is EntityType.DOMAIN:
        # An FQDN in a machine-ish field is a hostname, not a DNS query.
        if _HOST_NAMES.search(lowered):
            return "host.name"
        return "url.domain" if "url" in lowered else "dns.question.name"
    if entity is EntityType.URL:
        return "url.full"
    if entity is EntityType.EMAIL:
        return "email.from.address" if "from" in lowered or "sender" in lowered else "user.email"
    if entity is EntityType.HASH:
        return "file.hash.sha256" if "sha256" in lowered else "file.hash.md5" if "md5" in lowered else "hash.value"
    if entity is EntityType.FILE_PATH:
        return "file.path"
    if entity is EntityType.PROCESS_NAME:
        return "process.name"
    return _NAME_TO_ECS.get(lowered)


def index_summary(index: IntegrationIndex | None) -> str:
    if index is None:
        return "integration index: not available (corpus not cloned)"
    return (
        f"integration index: {len(index.data_streams)} data streams from "
        f"{index.pipeline_files} pipeline files, {len(index.ecs_fields)} ECS fields"
        + (f", {index.parse_failures} unparsable" if index.parse_failures else "")
    )
