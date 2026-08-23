"""ABLE hypotheses and the default library per data category (BLUEPRINT 5.5).

ABLE is the scoping frame from modern threat hunting: **A**ctor, **B**ehavior,
**L**ocation, **E**vidence. It is used here for a narrower question than a hunt
asks. A hunt asks "did this happen?"; this engine works from a static sample and
asks "could a rule for this behavior be built from this data at all?"

When matching finds nothing, the data category from profiling picks which
hypotheses are worth asking. Authentication logs get credential-abuse
hypotheses, DNS logs get tunnelling and DGA, and so on, exactly as
docs/BLUEPRINT.md 5.2 describes.

`Hypothesis.evidence` is the human-readable sentence the plan's schema calls
for. `evidence_requirements` is the same statement in a form the validator can
actually check, because "which fields does this need" has to be machine-checkable
for the reassess step to mean anything.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from engine.profiling.data_classifier import DataCategory
from engine.profiling.entity_recognition import EntityType
from engine.profiling.field_profiler import LogFingerprint


class EvidenceRequirement(BaseModel):
    """One field a hypothesis needs, described by every name it might arrive under."""

    label: str
    ecs_fields: list[str] = Field(default_factory=list)
    entity_types: list[EntityType] = Field(default_factory=list)
    name_keywords: list[str] = Field(default_factory=list)
    # Optional evidence sharpens a rule but does not block building one.
    required: bool = True


class Hypothesis(BaseModel):
    """One ABLE-structured detection hypothesis."""

    actor: str
    behavior: str
    location: str
    evidence: str

    # --- machine-checkable form of the above, for engine/hypothesis/validator.py
    evidence_requirements: list[EvidenceRequirement] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    # What rule type this behavior implies. A hint for the contextual-filtering
    # check and for the Phase 3 classifier, not a classification itself.
    implied_rule_type: str | None = None
    # True when the behavior can only be judged against a normal baseline
    # (first-seen detection, volume anomalies).
    needs_baseline: bool = False
    # Fields a threshold or sequence rule would group by.
    correlation_requirements: list[EvidenceRequirement] = Field(default_factory=list)

    @property
    def required_evidence(self) -> list[EvidenceRequirement]:
        return [requirement for requirement in self.evidence_requirements if requirement.required]


class HypothesisTemplate(BaseModel):
    """A hypothesis without its Location, which comes from the sample."""

    actor: str
    behavior: str
    evidence: str
    evidence_requirements: list[EvidenceRequirement] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    implied_rule_type: str | None = None
    needs_baseline: bool = False
    correlation_requirements: list[EvidenceRequirement] = Field(default_factory=list)

    def at(self, location: str) -> Hypothesis:
        return Hypothesis(location=location, **self.model_dump())


# --------------------------------------------------------------------------
# Reusable evidence requirements.
# --------------------------------------------------------------------------
_TIMESTAMP = EvidenceRequirement(
    label="event timestamp",
    ecs_fields=["@timestamp"],
    name_keywords=["timestamp", "datetime", "eventtime", "date", "time", "created"],
)
_SOURCE_ADDRESS = EvidenceRequirement(
    label="source address",
    ecs_fields=["source.ip", "client.ip", "related.ip"],
    entity_types=[EntityType.IP],
    name_keywords=["srcip", "clientip", "ipaddress", "source_ip", "src_ip", "remoteip"],
)
_DESTINATION_ADDRESS = EvidenceRequirement(
    label="destination address",
    ecs_fields=["destination.ip", "server.ip"],
    entity_types=[EntityType.IP],
    name_keywords=["dstip", "destip", "dest_ip", "destination_ip", "targetip"],
)
_DESTINATION_PORT = EvidenceRequirement(
    label="destination port",
    ecs_fields=["destination.port"],
    entity_types=[EntityType.PORT],
    name_keywords=["dstport", "destport", "destination_port", "dport"],
)
_USER_IDENTITY = EvidenceRequirement(
    label="user identity",
    ecs_fields=["user.name", "source.user.name", "user.target.name"],
    entity_types=[EntityType.USER],
    name_keywords=["username", "user", "account", "targetusername", "principal", "samaccountname"],
)
_OUTCOME = EvidenceRequirement(
    label="outcome or status",
    ecs_fields=["event.outcome", "http.response.status_code", "event.action"],
    name_keywords=["status", "result", "outcome", "action", "response", "success", "failure", "substatus"],
)
_URL_PATH = EvidenceRequirement(
    label="request path",
    ecs_fields=["url.path", "url.original"],
    name_keywords=["uri", "url", "path", "requestpath", "endpoint"],
)
_URL_QUERY = EvidenceRequirement(
    label="request query or body",
    ecs_fields=["url.query"],
    name_keywords=["query", "querystring", "body", "payload", "args"],
)
_HTTP_METHOD = EvidenceRequirement(
    label="request method",
    ecs_fields=["http.request.method"],
    name_keywords=["method", "verb", "requestmethod"],
    required=False,
)
_BYTES = EvidenceRequirement(
    label="transferred bytes",
    ecs_fields=["network.bytes", "source.bytes", "destination.bytes"],
    name_keywords=["byte", "bytes", "sentbyte", "rcvdbyte", "size", "length"],
)
_DNS_QUERY = EvidenceRequirement(
    label="queried name",
    ecs_fields=["dns.question.name"],
    entity_types=[EntityType.DOMAIN],
    name_keywords=["query", "qname", "domain", "hostname_queried", "question"],
)
_DNS_TYPE = EvidenceRequirement(
    label="query type",
    ecs_fields=["dns.question.type"],
    name_keywords=["qtype", "querytype", "record_type", "rrtype"],
    required=False,
)
_PROCESS = EvidenceRequirement(
    label="process name or image",
    ecs_fields=["process.name", "process.executable"],
    entity_types=[EntityType.PROCESS_NAME],
    name_keywords=["process", "image", "executable", "binary", "proc"],
)
_COMMAND_LINE = EvidenceRequirement(
    label="command line",
    ecs_fields=["process.command_line"],
    name_keywords=["commandline", "command_line", "cmdline", "args"],
)
_PARENT_PROCESS = EvidenceRequirement(
    label="parent process",
    ecs_fields=["process.parent.name", "process.parent.executable"],
    name_keywords=["parentimage", "parent_process", "parentcommandline", "ppid"],
    required=False,
)
_HOST = EvidenceRequirement(
    label="host identity",
    ecs_fields=["host.name", "observer.name"],
    name_keywords=["host", "computer", "hostname", "devname", "machine", "workstation"],
)
_INDICATOR = EvidenceRequirement(
    label="indicator value",
    ecs_fields=["threat.indicator.ip", "threat.indicator.url.full", "threat.indicator.file.hash.sha256"],
    entity_types=[EntityType.IP, EntityType.DOMAIN, EntityType.HASH, EntityType.URL],
    name_keywords=["indicator", "ioc", "observable", "value"],
)


# --------------------------------------------------------------------------
# Default hypotheses per data category. Two per category: one that a simple
# per-event rule could satisfy, one that needs correlation or a baseline, so
# the validation output shows both the cheap and the expensive path.
# --------------------------------------------------------------------------
HYPOTHESIS_LIBRARY: dict[DataCategory, list[HypothesisTemplate]] = {
    DataCategory.AUTHENTICATION_LOGS: [
        HypothesisTemplate(
            actor="Opportunistic external attacker or commodity credential-stuffing botnet",
            behavior="Brute force or password spraying against exposed accounts (T1110)",
            evidence="A user identity, an authentication outcome, the source address, and a timestamp, "
                     "so repeated failures can be counted per source within a window.",
            evidence_requirements=[_USER_IDENTITY, _OUTCOME, _SOURCE_ADDRESS, _TIMESTAMP],
            mitre_techniques=["T1110"],
            implied_rule_type="threshold",
            correlation_requirements=[_SOURCE_ADDRESS, _USER_IDENTITY],
        ),
        HypothesisTemplate(
            actor="Attacker in possession of valid credentials, or a misused insider account",
            behavior="Authentication from an account, host, or time never seen before (T1078)",
            evidence="A user identity plus the host or address the authentication came from, over enough "
                     "history to know what 'never seen before' means.",
            evidence_requirements=[_USER_IDENTITY, _SOURCE_ADDRESS, _TIMESTAMP, _HOST],
            mitre_techniques=["T1078"],
            implied_rule_type="new_terms",
            needs_baseline=True,
            correlation_requirements=[_USER_IDENTITY],
        ),
    ],
    DataCategory.APPLICATION_LOGS: [
        HypothesisTemplate(
            actor="Untargeted internet scanning, or an attacker probing a known application",
            behavior="Exploitation attempt against a public-facing application (T1190)",
            evidence="The request path and query or body, so injection and traversal payloads are visible, "
                     "plus the source address and the response status.",
            evidence_requirements=[_URL_PATH, _URL_QUERY, _SOURCE_ADDRESS, _OUTCOME, _HTTP_METHOD],
            mitre_techniques=["T1190"],
            implied_rule_type="custom_query",
        ),
        HypothesisTemplate(
            actor="Credential-stuffing operator reusing breached password lists",
            behavior="High-volume failed authentication against an application login endpoint (T1110.004)",
            evidence="The request path, the response status distinguishing failure from success, the source "
                     "address, and timestamps fine enough to count attempts in a window.",
            evidence_requirements=[_URL_PATH, _OUTCOME, _SOURCE_ADDRESS, _TIMESTAMP],
            mitre_techniques=["T1110.004"],
            implied_rule_type="threshold",
            correlation_requirements=[_SOURCE_ADDRESS],
        ),
    ],
    DataCategory.NETWORK_LOGS: [
        HypothesisTemplate(
            actor="Attacker who already has a foothold and is mapping the internal network",
            behavior="Internal network or port scanning (T1046)",
            evidence="Source and destination addresses plus destination port, so fan-out from one source "
                     "across many ports or hosts can be counted.",
            evidence_requirements=[_SOURCE_ADDRESS, _DESTINATION_ADDRESS, _DESTINATION_PORT, _TIMESTAMP],
            mitre_techniques=["T1046"],
            implied_rule_type="threshold",
            correlation_requirements=[_SOURCE_ADDRESS],
        ),
        HypothesisTemplate(
            actor="Established intruder operating a command-and-control channel",
            behavior="Exfiltration or C2 over an unusual destination or port (T1048, T1071)",
            evidence="Destination address and port with transferred byte counts, over enough history to "
                     "tell an unusual destination from a routine one.",
            evidence_requirements=[_SOURCE_ADDRESS, _DESTINATION_ADDRESS, _DESTINATION_PORT, _BYTES, _TIMESTAMP],
            mitre_techniques=["T1048", "T1071"],
            implied_rule_type="new_terms",
            needs_baseline=True,
            correlation_requirements=[_SOURCE_ADDRESS, _DESTINATION_ADDRESS],
        ),
    ],
    DataCategory.DNS_LOGS: [
        HypothesisTemplate(
            actor="Malware using DNS as a covert channel",
            behavior="DNS tunnelling: encoded data in query names (T1071.004)",
            evidence="The queried name and the querying client, with query type, so long or high-entropy "
                     "labels can be spotted per client.",
            evidence_requirements=[_DNS_QUERY, _SOURCE_ADDRESS, _TIMESTAMP, _DNS_TYPE],
            mitre_techniques=["T1071.004"],
            implied_rule_type="custom_query",
            correlation_requirements=[_SOURCE_ADDRESS],
        ),
        HypothesisTemplate(
            actor="Malware resolving algorithmically generated command-and-control domains",
            behavior="Resolution of newly seen or algorithmically generated domains (T1568.002)",
            evidence="The queried name per client, over enough history to establish which domains are "
                     "already routine for this environment.",
            evidence_requirements=[_DNS_QUERY, _SOURCE_ADDRESS, _TIMESTAMP],
            mitre_techniques=["T1568.002"],
            implied_rule_type="new_terms",
            needs_baseline=True,
            correlation_requirements=[_SOURCE_ADDRESS],
        ),
    ],
    DataCategory.ENDPOINT_DATA: [
        HypothesisTemplate(
            actor="Attacker executing tooling after initial access",
            behavior="Suspicious command interpreter or living-off-the-land execution (T1059)",
            evidence="The process image and its full command line, with the parent process to establish "
                     "the execution chain.",
            evidence_requirements=[_PROCESS, _COMMAND_LINE, _HOST, _PARENT_PROCESS],
            mitre_techniques=["T1059"],
            implied_rule_type="custom_query",
        ),
        HypothesisTemplate(
            actor="Attacker escalating from a foothold toward domain credentials",
            behavior="Credential dumping from process memory or registry hives (T1003)",
            evidence="The process image, its command line, and the account it ran as, so access to LSASS "
                     "or SAM by unexpected tooling is visible.",
            evidence_requirements=[_PROCESS, _COMMAND_LINE, _USER_IDENTITY, _HOST],
            mitre_techniques=["T1003"],
            implied_rule_type="eql",
            correlation_requirements=[_HOST],
        ),
    ],
    DataCategory.SYSTEM_LOGS: [
        HypothesisTemplate(
            actor="Attacker establishing persistence on a compromised host",
            behavior="Creation or modification of a service, scheduled task, or startup entry (T1543)",
            evidence="The host, the object being changed, the account making the change, and a timestamp.",
            evidence_requirements=[_HOST, _OUTCOME, _USER_IDENTITY, _TIMESTAMP],
            mitre_techniques=["T1543"],
            implied_rule_type="custom_query",
        ),
        HypothesisTemplate(
            actor="Attacker covering their tracks after acting on objectives",
            behavior="Log clearing or audit policy tampering (T1070)",
            evidence="An event action or code identifying the clearing operation, the account responsible, "
                     "and the host it happened on.",
            evidence_requirements=[_OUTCOME, _USER_IDENTITY, _HOST, _TIMESTAMP],
            mitre_techniques=["T1070"],
            implied_rule_type="custom_query",
        ),
    ],
    DataCategory.THREAT_INTEL_FEED: [
        HypothesisTemplate(
            actor="Any actor whose infrastructure is already published in threat intelligence",
            behavior="Telemetry matching a known malicious indicator",
            evidence="An indicator value with its type, so the feed can be joined against event telemetry.",
            evidence_requirements=[_INDICATOR, _TIMESTAMP],
            mitre_techniques=[],
            implied_rule_type="indicator_match",
        ),
    ],
}

# Used when profiling could not name a data category at all.
UNCLASSIFIED_HYPOTHESIS = HypothesisTemplate(
    actor="Unknown, because the log source itself is unidentified",
    behavior="No behavior can be hypothesized before the log source is known",
    evidence="Enough of a field inventory to recognise the source: an event timestamp, an actor "
             "(user or host), and an action or outcome.",
    evidence_requirements=[_TIMESTAMP, _HOST, _OUTCOME],
    mitre_techniques=[],
    implied_rule_type=None,
)


def build_hypotheses(fingerprint: LogFingerprint) -> list[Hypothesis]:
    """Pick the hypotheses worth asking of this sample.

    The data category decides. An unclassified sample gets the single
    placeholder hypothesis, whose rejection says the source must be identified
    first, rather than a fabricated guess about what might be in it.
    """
    location = _describe_location(fingerprint)

    if fingerprint.data_category is None:
        return [UNCLASSIFIED_HYPOTHESIS.at(location)]

    templates = HYPOTHESIS_LIBRARY.get(fingerprint.data_category)
    if not templates:
        return [UNCLASSIFIED_HYPOTHESIS.at(location)]

    return [template.at(location) for template in templates]


def _describe_location(fingerprint: LogFingerprint) -> str:
    """The Location leg of ABLE: which log source, in this sample's own terms."""
    parts = [
        part for part in (
            fingerprint.inferred_product,
            fingerprint.inferred_service,
            fingerprint.inferred_category,
        ) if part
    ]
    source = " / ".join(parts) if parts else "unidentified log source"
    category = fingerprint.data_category.value if fingerprint.data_category else "uncategorised"
    return f"{source} ({category}), {fingerprint.record_count} events in the sample"
