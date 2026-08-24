"""Pick the Elastic rule type a candidate should be built as (BLUEPRINT 5.4).

The decision table from the blueprint, encoded as explicit rules. Deliberately
not a model: the reason a rule type was chosen has to be readable by the analyst
who signs it off, and traceable to a row of that table.

The method is capability-first rather than type-first. Each signal identifies a
*capability the detection requires* - counting events, ordering them, joining to
an indicator index - and the chosen type is the simplest one that provides every
required capability. That is what the blueprint's "use the simplest type that is
enough" instruction means in practice, and it keeps the answer stable when two
rows of the table both look applicable.

Signals come from three places, in descending order of authority:

1. **The taxonomy entry's detection logic.** An `aggregation` block with a count
   is not a hint, it is a statement that counting is required.
2. **The curator's `suggested_rule_type`**, when the entry names one.
3. **The MITRE technique and the sample's entity types.** These never force a
   type; they surface *alternatives* an analyst may prefer. A brute-force
   technique can be written per event, but is usually better as a threshold.
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable, Sequence

from pydantic import BaseModel, Field

from engine.matching.candidate import MatchCandidate
from engine.profiling.entity_recognition import EntityType
from engine.profiling.field_profiler import LogFingerprint
from engine.storage.taxonomy_store import TaxonomyEntry


class ElasticRuleType(str, Enum):
    CUSTOM_QUERY = "custom_query"
    EQL = "eql"
    THRESHOLD = "threshold"
    ESQL = "esql"
    INDICATOR_MATCH = "indicator_match"
    NEW_TERMS = "new_terms"
    MACHINE_LEARNING = "machine_learning"


class DetectionCapability(str, Enum):
    """What a detection needs to be able to do, independent of rule type."""

    SINGLE_EVENT = "single_event"
    COUNT_AGGREGATION = "count_aggregation"
    COMPUTED_AGGREGATION = "computed_aggregation"
    EVENT_SEQUENCE = "event_sequence"
    FIRST_SEEN = "first_seen"
    INDICATOR_JOIN = "indicator_join"
    ADAPTIVE_BASELINE = "adaptive_baseline"


class RuleTypeDecision(BaseModel):
    """The recommended rule type, and why."""

    elastic_type: ElasticRuleType
    reasoning: str
    # Types that could also express this, simplest first. BLUEPRINT 5.4 asks for
    # the simplest sufficient type, but the analyst should see what was passed over.
    alternatives: list[ElasticRuleType] = Field(default_factory=list)
    # Things true of this sample that would block or weaken the rule in production.
    caveats: list[str] = Field(default_factory=list)
    # BLUEPRINT 5.4's mapping onto the broader threat-hunting technique categories.
    hunting_technique: str | None = None


# Simplest first. Used to break ties and to order alternatives.
_COMPLEXITY: dict[ElasticRuleType, int] = {
    ElasticRuleType.CUSTOM_QUERY: 1,
    ElasticRuleType.THRESHOLD: 2,
    ElasticRuleType.NEW_TERMS: 3,
    ElasticRuleType.INDICATOR_MATCH: 4,
    ElasticRuleType.EQL: 5,
    ElasticRuleType.ESQL: 6,
    ElasticRuleType.MACHINE_LEARNING: 7,
}

_CAPABILITY_TO_TYPE: dict[DetectionCapability, ElasticRuleType] = {
    DetectionCapability.SINGLE_EVENT: ElasticRuleType.CUSTOM_QUERY,
    DetectionCapability.COUNT_AGGREGATION: ElasticRuleType.THRESHOLD,
    DetectionCapability.FIRST_SEEN: ElasticRuleType.NEW_TERMS,
    DetectionCapability.INDICATOR_JOIN: ElasticRuleType.INDICATOR_MATCH,
    DetectionCapability.EVENT_SEQUENCE: ElasticRuleType.EQL,
    DetectionCapability.COMPUTED_AGGREGATION: ElasticRuleType.ESQL,
    DetectionCapability.ADAPTIVE_BASELINE: ElasticRuleType.MACHINE_LEARNING,
}

_RULE_TYPE_BY_NAME = {rule_type.value: rule_type for rule_type in ElasticRuleType}

# BLUEPRINT 5.4: Elastic's rule types operationalise these hunting techniques.
_HUNTING_TECHNIQUE: dict[ElasticRuleType, str] = {
    ElasticRuleType.EQL: "Behavioral Analysis (deviation from expected behavior patterns)",
    ElasticRuleType.THRESHOLD: "Trend & Statistical Analysis (aggregation over time)",
    ElasticRuleType.ESQL: "Trend & Statistical Analysis (computed aggregation)",
    ElasticRuleType.INDICATOR_MATCH: "Threat Intelligence Correlation",
    ElasticRuleType.NEW_TERMS: "Anomaly Detection (baseline deviation, first-seen)",
    ElasticRuleType.MACHINE_LEARNING: "Statistical and Machine Learning Analysis",
}

# Keys a taxonomy entry's detection_logic uses to declare what it needs.
_LOGIC_KEY_CAPABILITIES: dict[str, DetectionCapability] = {
    "aggregation": DetectionCapability.COUNT_AGGREGATION,
    "threshold": DetectionCapability.COUNT_AGGREGATION,
    "count": DetectionCapability.COUNT_AGGREGATION,
    "sequence": DetectionCapability.EVENT_SEQUENCE,
    "ordered": DetectionCapability.EVENT_SEQUENCE,
    "followed_by": DetectionCapability.EVENT_SEQUENCE,
    "stats": DetectionCapability.COMPUTED_AGGREGATION,
    "eval": DetectionCapability.COMPUTED_AGGREGATION,
    "computed": DetectionCapability.COMPUTED_AGGREGATION,
    "first_seen": DetectionCapability.FIRST_SEEN,
    "new_terms": DetectionCapability.FIRST_SEEN,
    "indicator": DetectionCapability.INDICATOR_JOIN,
    "intel_match": DetectionCapability.INDICATOR_JOIN,
    "baseline": DetectionCapability.ADAPTIVE_BASELINE,
    "anomaly": DetectionCapability.ADAPTIVE_BASELINE,
}

# Techniques whose usual expression is volume-based or first-seen. These raise
# an alternative, never a requirement: the same technique can be detected per
# event, and forcing a threshold would change what the rule means.
_VOLUME_TECHNIQUE_PREFIXES = ("T1110", "T1046", "T1499", "T1498", "T1595")
_FIRST_SEEN_TECHNIQUE_PREFIXES = ("T1078", "T1568", "T1583", "T1584")

_INTEL_MATCHABLE_ENTITIES = {EntityType.IP, EntityType.DOMAIN, EntityType.HASH, EntityType.URL}


def classify(
    candidate: MatchCandidate,
    fingerprint: LogFingerprint,
    *,
    taxonomy_entry: TaxonomyEntry | None = None,
) -> RuleTypeDecision:
    """Recommend the Elastic rule type for one match candidate."""
    required, evidence = _required_capabilities(candidate, taxonomy_entry)
    elastic_type = _resolve(required)

    alternatives = _alternatives(elastic_type, candidate, fingerprint, taxonomy_entry)
    caveats = _caveats(elastic_type, fingerprint)

    return RuleTypeDecision(
        elastic_type=elastic_type,
        reasoning=_reasoning(elastic_type, required, evidence),
        alternatives=alternatives,
        caveats=caveats,
        hunting_technique=_HUNTING_TECHNIQUE.get(elastic_type),
    )


def _required_capabilities(
    candidate: MatchCandidate,
    entry: TaxonomyEntry | None,
) -> tuple[set[DetectionCapability], list[str]]:
    """What the detection must be able to do, and the evidence for each claim."""
    capabilities: set[DetectionCapability] = {DetectionCapability.SINGLE_EVENT}
    evidence: list[str] = []

    if entry is not None:
        for key in entry.detection_logic:
            capability = _LOGIC_KEY_CAPABILITIES.get(key.lower())
            if capability:
                capabilities.add(capability)
                evidence.append(f"the entry's detection logic declares '{key}'")

        suggested = _RULE_TYPE_BY_NAME.get((entry.suggested_rule_type or "").lower())
        if suggested:
            for capability, rule_type in _CAPABILITY_TO_TYPE.items():
                if rule_type is suggested:
                    if capability not in capabilities:
                        capabilities.add(capability)
                        evidence.append(f"the curator recorded suggested_rule_type={suggested.value}")
                    break

    if not evidence:
        source = "the Sigma rule" if candidate.rule_ref.startswith("sigma:") else "the entry"
        evidence.append(f"{source} matches within a single event, with no aggregation or ordering")

    return capabilities, evidence


def _resolve(capabilities: set[DetectionCapability]) -> ElasticRuleType:
    """Pick the simplest rule type that satisfies every required capability."""
    needs_count = DetectionCapability.COUNT_AGGREGATION in capabilities
    needs_sequence = DetectionCapability.EVENT_SEQUENCE in capabilities

    # Only ES|QL expresses both ordering and aggregation in one rule.
    if needs_count and needs_sequence:
        return ElasticRuleType.ESQL

    candidates = {_CAPABILITY_TO_TYPE[capability] for capability in capabilities}
    return max(candidates, key=lambda rule_type: _COMPLEXITY[rule_type])


def _alternatives(
    chosen: ElasticRuleType,
    candidate: MatchCandidate,
    fingerprint: LogFingerprint,
    entry: TaxonomyEntry | None,
) -> list[ElasticRuleType]:
    """Types an analyst might reasonably prefer instead, simplest first."""
    options: set[ElasticRuleType] = set()
    techniques = [technique.upper() for technique in candidate.mitre_techniques]

    if any(technique.startswith(_VOLUME_TECHNIQUE_PREFIXES) for technique in techniques):
        options.add(ElasticRuleType.THRESHOLD)
    if any(technique.startswith(_FIRST_SEEN_TECHNIQUE_PREFIXES) for technique in techniques):
        options.add(ElasticRuleType.NEW_TERMS)

    # Indicator match is deliberately NOT offered here. BLUEPRINT 5.4 row 5 keys
    # it on the sample carrying intel-matchable entities, which is a property of
    # the data, not of any one candidate: offering it against every rule in a log
    # that happens to contain an IP is noise. It is reported once per sample by
    # intel_matchable_entities() instead.

    if entry is not None and DetectionCapability.ADAPTIVE_BASELINE.value in entry.detection_logic:
        options.add(ElasticRuleType.MACHINE_LEARNING)

    options.discard(chosen)
    return sorted(options, key=lambda rule_type: _COMPLEXITY[rule_type])


def _caveats(elastic_type: ElasticRuleType, fingerprint: LogFingerprint) -> list[str]:
    """Facts about this sample that would weaken or block the rule in production."""
    caveats: list[str] = []
    has_timestamp = any(profile.dtype == "timestamp" for profile in fingerprint.profiles)

    if elastic_type in {ElasticRuleType.THRESHOLD, ElasticRuleType.EQL, ElasticRuleType.ESQL}:
        if not has_timestamp:
            caveats.append(
                "no timestamp field was profiled in this sample; a time-windowed rule cannot be "
                "built until one is mapped to @timestamp"
            )
        if not _has_groupable_entity(fingerprint):
            caveats.append(
                "no entity field (address, user, host) was recognised to group events by, which a "
                "windowed rule needs"
            )

    if elastic_type in {ElasticRuleType.NEW_TERMS, ElasticRuleType.MACHINE_LEARNING}:
        caveats.append(
            f"this rule type needs historical volume to know what is new; the sample holds "
            f"{fingerprint.record_count} events, which cannot establish that baseline"
        )

    if elastic_type is ElasticRuleType.INDICATOR_MATCH:
        caveats.append(
            "requires an indicator index in Elastic to join against; the sample alone cannot "
            "demonstrate the rule will fire"
        )

    if elastic_type is ElasticRuleType.MACHINE_LEARNING:
        caveats.append(
            "requires an active ML job and a platform licence that includes it; confirm both before "
            "committing this to the SOW"
        )

    return caveats


def intel_matchable_entities(fingerprint: LogFingerprint) -> list[EntityType]:
    """Entity types in this sample that an Indicator Match rule could join on.

    BLUEPRINT 5.4 row 5, reported at sample level: it says an indicator match
    rule is *possible* against this data, which is a different statement from
    any particular candidate being better expressed that way.
    """
    present = {
        profile.entity_type for profile in fingerprint.profiles
        if profile.entity_type in _INTEL_MATCHABLE_ENTITIES
    }
    return sorted(present, key=lambda entity: entity.value)


def _has_groupable_entity(fingerprint: LogFingerprint) -> bool:
    groupable = {EntityType.IP, EntityType.USER, EntityType.DOMAIN, EntityType.PROCESS_NAME}
    return any(profile.entity_type in groupable for profile in fingerprint.profiles)


def _reasoning(
    elastic_type: ElasticRuleType,
    capabilities: Iterable[DetectionCapability],
    evidence: Sequence[str],
) -> str:
    needed = sorted(
        (capability for capability in capabilities if capability is not DetectionCapability.SINGLE_EVENT),
        key=lambda capability: _COMPLEXITY[_CAPABILITY_TO_TYPE[capability]],
    )

    if not needed:
        return (
            f"Simple field match satisfiable within one event, so {elastic_type.value} is the "
            f"simplest sufficient type ({evidence[0]})."
        )

    requirement_text = ", ".join(capability.value.replace("_", " ") for capability in needed)
    return (
        f"Detection requires {requirement_text}, which {elastic_type.value} is the simplest type to "
        f"provide ({'; '.join(evidence)})."
    )
