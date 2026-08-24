"""Classify what kind of log a sample is (docs/BLUEPRINT.md 5.2).

Produces two things the rest of the engine needs:

* the **Sigma logsource triple** (category / product / service), which is what
  ``sigma_matcher`` compares rules against;
* the **data category**, which decides the default hypotheses in the NO MATCH
  path (Phase 2).

Both come from field-name signatures, not from values, so classification stays
cheap and explainable: every result carries the field names that produced it.

Signatures are meant to grow, one per log source the team meets. Adding one is
appending to ``SIGNATURES``. A source with no signature is not an error -- the
triple comes back as None and matching falls back to what the fallback data
category can support, which is exactly the "no automatic match" case
docs/BLUEPRINT.md §2 says to report honestly rather than paper over.
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable, Sequence

from pydantic import BaseModel, Field


class DataCategory(str, Enum):
    NETWORK_LOGS = "network_logs"
    ENDPOINT_DATA = "endpoint_data"
    AUTHENTICATION_LOGS = "authentication_logs"
    APPLICATION_LOGS = "application_logs"
    DNS_LOGS = "dns_logs"
    SYSTEM_LOGS = "system_logs"
    THREAT_INTEL_FEED = "threat_intel_feed"


class LogSourceSignature(BaseModel):
    """One recognizable log source, keyed on the field names it always carries."""

    name: str
    category: str | None = None
    product: str | None = None
    service: str | None = None
    data_category: DataCategory
    # Every one of these must be present for the signature to apply at all.
    required: frozenset[str]
    # Each of these that is present raises confidence.
    indicative: frozenset[str] = frozenset()
    note: str = ""


class Classification(BaseModel):
    """What the sample looks like, and why."""

    inferred_category: str | None = None
    inferred_product: str | None = None
    inferred_service: str | None = None
    data_category: DataCategory | None = None
    confidence: float = 0.0
    signature: str | None = None
    evidence: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Known log sources.
#
# Cloudflare and FortiGate field names were taken from the ingest pipelines in
# the local elastic/integrations clone, not from memory. Windows Security field
# names follow the Sigma windows taxonomy.
# --------------------------------------------------------------------------
SIGNATURES: tuple[LogSourceSignature, ...] = (
    LogSourceSignature(
        name="cloudflare_firewall_events",
        category="webserver",
        product="cloudflare",
        service="firewall_events",
        data_category=DataCategory.APPLICATION_LOGS,
        required=frozenset({"clientip", "clientrequesthost", "action"}),
        indicative=frozenset({
            "rayid", "ruleid", "source", "clientrequestpath", "clientrequestquery",
            "clientrequestmethod", "edgeresponsestatus", "originresponsestatus",
            "clientcountry", "clientasn", "clientrequestuseragent", "kind", "edgecolocode",
        }),
    ),
    LogSourceSignature(
        name="cloudflare_http_requests",
        category="webserver",
        product="cloudflare",
        service="http_requests",
        data_category=DataCategory.APPLICATION_LOGS,
        required=frozenset({"clientip", "clientrequesturi"}),
        indicative=frozenset({
            "edgestarttimestamp", "edgeresponsestatus", "clientrequestmethod",
            "clientrequesthost", "rayid", "originresponsestatus", "clientcountry",
            # WAF Attack Score fields, present when the Logpush job selects them.
            # This is the shape that reaches Sentinel in practice, and it carries
            # no RuleID at all.
            "wafattackscore", "wafattackscoreclass", "wafsqliattackscore",
            "wafxssattackscore", "wafrceattackscore", "wafaction",
            "clientipclass", "originip",
        }),
    ),
    LogSourceSignature(
        name="fortinet_fortigate",
        category="firewall",
        product="fortinet_fortigate",
        service=None,
        data_category=DataCategory.NETWORK_LOGS,
        required=frozenset({"srcip", "dstip"}),
        indicative=frozenset({
            "devname", "devid", "policyid", "sessionid", "srcport", "dstport",
            "srcintf", "dstintf", "sentbyte", "rcvdbyte", "action", "type", "subtype",
            "service", "proto", "logid", "vd", "level",
        }),
    ),
    LogSourceSignature(
        name="windows_security",
        product="windows",
        service="security",
        data_category=DataCategory.AUTHENTICATION_LOGS,
        required=frozenset({"eventid", "computer"}),
        indicative=frozenset({
            "subjectusername", "targetusername", "targetdomainname", "logontype",
            "ipaddress", "ipport", "processname", "channel", "provider", "logonprocessname",
            "authenticationpackagename", "workstationname", "status", "substatus",
        }),
        note="EventID drives the sub-classification; 4624/4625/4768 are authentication.",
    ),
    LogSourceSignature(
        name="windows_sysmon_process",
        category="process_creation",
        product="windows",
        service="sysmon",
        data_category=DataCategory.ENDPOINT_DATA,
        required=frozenset({"image", "commandline"}),
        indicative=frozenset({
            "parentimage", "parentcommandline", "processid", "processguid", "user",
            "hashes", "originalfilename", "currentdirectory", "integritylevel", "computer",
        }),
    ),
    LogSourceSignature(
        name="generic_webserver_w3c",
        category="webserver",
        data_category=DataCategory.APPLICATION_LOGS,
        required=frozenset({"cs-method"}),
        indicative=frozenset({
            "cs-uri-stem", "cs-uri-query", "sc-status", "cs-user-agent", "cs-host",
            "c-ip", "cs-referer", "cs-uri", "s-ip", "time-taken",
        }),
        note="The field names Sigma's webserver rules are written against.",
    ),
    LogSourceSignature(
        name="ecs_webserver",
        category="webserver",
        data_category=DataCategory.APPLICATION_LOGS,
        required=frozenset({"http.request.method"}),
        indicative=frozenset({
            "url.path", "url.query", "url.domain", "http.response.status_code",
            "user_agent.original", "source.ip", "destination.ip", "event.action",
        }),
        note="Already ECS-normalized; no mapping work needed before rule creation.",
    ),
    LogSourceSignature(
        name="generic_dns",
        category="dns",
        data_category=DataCategory.DNS_LOGS,
        required=frozenset({"query"}),
        indicative=frozenset({"qtype", "qclass", "rcode", "answer", "answers", "rrtype", "record_type"}),
    ),
    LogSourceSignature(
        name="ecs_dns",
        category="dns",
        data_category=DataCategory.DNS_LOGS,
        required=frozenset({"dns.question.name"}),
        indicative=frozenset({
            "dns.question.type", "dns.response_code", "dns.answers.data",
            "source.ip", "destination.ip",
        }),
    ),
    LogSourceSignature(
        name="zeek_conn",
        category="network_connection",
        product="zeek",
        service="conn",
        data_category=DataCategory.NETWORK_LOGS,
        required=frozenset({"id.orig_h", "id.resp_h"}),
        indicative=frozenset({"id.orig_p", "id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes", "conn_state", "uid"}),
    ),
    LogSourceSignature(
        name="ecs_network_flow",
        category="firewall",
        data_category=DataCategory.NETWORK_LOGS,
        required=frozenset({"source.ip", "destination.ip"}),
        indicative=frozenset({
            "source.port", "destination.port", "network.protocol", "network.bytes",
            "event.action", "network.direction", "observer.name",
        }),
    ),
)

# Fallback: keyword groups over field names, used when no signature applies.
# Only the data category can be guessed this way -- product and service cannot,
# and inventing them would be worse than leaving them unset.
_FALLBACK_KEYWORDS: tuple[tuple[DataCategory, frozenset[str]], ...] = (
    (DataCategory.AUTHENTICATION_LOGS, frozenset({
        "logon", "login", "signin", "auth", "credential", "password", "mfa", "otp",
        "account", "principal", "kerberos", "ntlm", "saml", "token",
    })),
    (DataCategory.DNS_LOGS, frozenset({"dns", "query", "qtype", "rcode", "nxdomain", "resolver", "domain"})),
    (DataCategory.ENDPOINT_DATA, frozenset({
        "process", "commandline", "command_line", "parent", "image", "executable",
        "sha256", "md5", "registry", "driver", "dll", "thread",
    })),
    (DataCategory.APPLICATION_LOGS, frozenset({
        "url", "uri", "http", "request", "response", "useragent", "user_agent",
        "referer", "referrer", "endpoint", "statuscode", "status_code", "path", "query",
    })),
    (DataCategory.NETWORK_LOGS, frozenset({
        "srcip", "dstip", "sourceip", "destip", "src", "dst", "port", "bytes",
        "packets", "protocol", "proto", "interface", "flow", "session", "firewall",
    })),
    (DataCategory.THREAT_INTEL_FEED, frozenset({
        "indicator", "ioc", "threat", "feed", "malware", "campaign", "actor", "tlp", "confidence",
    })),
    (DataCategory.SYSTEM_LOGS, frozenset({
        "syslog", "facility", "severity", "daemon", "kernel", "service", "unit", "pid", "hostname",
    })),
)


def classify(field_names: Iterable[str]) -> Classification:
    """Infer the Sigma logsource triple and data category from field names."""
    present = _normalize(field_names)
    if not present:
        return Classification()

    best: tuple[float, LogSourceSignature, list[str]] | None = None
    for signature in SIGNATURES:
        matched_required = signature.required & present
        if matched_required != signature.required:
            continue
        matched_indicative = signature.indicative & present
        total = len(signature.required) + len(signature.indicative)
        score = (len(matched_required) + len(matched_indicative)) / total if total else 0.0
        if best is None or score > best[0]:
            best = (score, signature, sorted(matched_required) + sorted(matched_indicative))

    if best is not None:
        score, signature, matched = best
        # A signature whose required fields are all present is already a strong
        # statement; the indicative fields refine it rather than gate it.
        confidence = min(1.0, 0.6 + 0.4 * score)
        return Classification(
            inferred_category=signature.category,
            inferred_product=signature.product,
            inferred_service=signature.service,
            data_category=signature.data_category,
            confidence=round(confidence, 2),
            signature=signature.name,
            evidence=[f"matched signature '{signature.name}' on: {', '.join(matched)}"],
        )

    category, hits = _fallback_data_category(present)
    if category is None:
        return Classification(evidence=["no log source signature matched, and no field-name keywords were recognizable"])

    return Classification(
        data_category=category,
        confidence=round(min(0.5, 0.15 * len(hits)), 2),
        evidence=[
            "no log source signature matched; data category guessed from field names: "
            + ", ".join(sorted(hits)),
        ],
    )


def _fallback_data_category(present: set[str]) -> tuple[DataCategory | None, set[str]]:
    best: tuple[int, DataCategory, set[str]] | None = None
    for category, keywords in _FALLBACK_KEYWORDS:
        hits = {name for name in present if any(keyword in name for keyword in keywords)}
        if not hits:
            continue
        if best is None or len(hits) > best[0]:
            best = (len(hits), category, hits)
    if best is None:
        return None, set()
    return best[1], best[2]


def _normalize(field_names: Iterable[str]) -> set[str]:
    """Lowercase every field name, and index dotted names by their last segment too.

    ``source.ip`` should satisfy a signature written as ``source.ip``, but a
    vendor field arriving as ``event.srcip`` should still satisfy ``srcip``.
    """
    present: set[str] = set()
    for name in field_names:
        lowered = name.strip().lower()
        if not lowered:
            continue
        present.add(lowered)
        if "." in lowered:
            present.add(lowered.rsplit(".", 1)[-1])
    return present


def signature_names() -> Sequence[str]:
    """Names of every known signature, for CLI/help output."""
    return tuple(signature.name for signature in SIGNATURES)
