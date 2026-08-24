"""Run a candidate's logic against the sample and predict its behaviour (BLUEPRINT 5.6).

Answers the question that decides whether a candidate is worth building: if this
rule went live, how often would it fire, and is that a workable number?

Three things happen here:

* **Backtest.** The candidate's detection logic is executed against the parsed
  sample. Sigma candidates are evaluated from pySigma's parsed condition tree;
  internal taxonomy entries from their stored `detection_logic`. Field names are
  resolved through the same ECS bridge matching used, so a rule written against
  `cs-method` runs against a column called `ClientRequestMethod`.
* **Alert volume, not event count.** A threshold rule that needs 20 failed logins
  produces one alert, not twenty. Aggregated candidates are bucketed by their own
  group-by and window before anything is counted.
* **Confidence tier.** Matching confidence, field completeness, and what the
  backtest actually did, combined into High / Medium / Low.

What this cannot do is honest about its own limits. A rule that matches nothing
is reported as unproven rather than as good news, and a projection from a
ten-minute sample is labelled unreliable rather than presented as a daily figure
someone might put in a SOW.
"""

from __future__ import annotations

import ast
import ipaddress
import re
from collections import defaultdict
from enum import Enum
from functools import lru_cache
from typing import Any, Sequence

from pydantic import BaseModel, Field

from engine.ingestion.schemas import LogRecord
from engine.matching.candidate import MatchCandidate
from engine.profiling.field_profiler import LogFingerprint
from engine.storage.taxonomy_store import TaxonomyEntry

# A rule matching more than this share of all events is unlikely to be a
# detection; it is a description of normal traffic.
NOISE_THRESHOLD = 0.05
# Below this many events, a match rate is not a rate. Two hits in a 37-event
# fixture is 5.4%, and calling that noisy would be an artefact of sample size.
MIN_EVENTS_FOR_NOISE = 100
# Alerts per day beyond which a single detection rule stops being triageable.
# A blunt operational ceiling, not a law; adjust it to the SOC's real capacity.
ALERT_VOLUME_CEILING = 100.0
# Below this span, multiplying up to a daily figure says more about the sample
# than about production.
RELIABLE_SPAN_SECONDS = 3600

_WINDOW_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_RESERVED_LOGIC_KEYS = {"condition", "aggregation"}


class ConfidenceTier(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class BacktestResult(BaseModel):
    """What the candidate's logic did against this sample."""

    evaluated: bool = False
    total_events: int = 0
    matched_events: int = 0
    # Alerts after aggregation. Equal to matched_events for per-event rules.
    alerts: int = 0
    match_rate: float = 0.0
    example_lines: list[int] = Field(default_factory=list)
    unsupported_reason: str | None = None
    aggregation_note: str | None = None


class PredictionResult(BaseModel):
    """Projected behaviour of the candidate, and how much to trust it."""

    estimated_alert_volume: float  # alerts per day
    confidence_tier: ConfidenceTier
    notes: str

    backtest: BacktestResult = Field(default_factory=BacktestResult)
    projection_basis: str = "not projectable"
    noisy: bool = False


class _Unsupported(Exception):
    """The logic uses a construct this evaluator does not implement."""


# ------------------------------------------------------------------ public API


def predict(
    candidate: MatchCandidate,
    records: Sequence[LogRecord],
    fingerprint: LogFingerprint,
    *,
    sigma_rule: Any | None = None,
    taxonomy_entry: TaxonomyEntry | None = None,
    log_rate_per_day: float | None = None,
) -> PredictionResult:
    """Backtest the candidate and project what it would do in production."""
    result = backtest(
        candidate, records, fingerprint,
        sigma_rule=sigma_rule, taxonomy_entry=taxonomy_entry,
    )

    span = _sample_span_seconds(records, fingerprint)
    volume, basis, projection_notes, reliable = _project(result, span, log_rate_per_day)

    noisy = (
        result.evaluated
        and result.total_events >= MIN_EVENTS_FOR_NOISE
        and result.match_rate > NOISE_THRESHOLD
    )
    if reliable and volume > ALERT_VOLUME_CEILING:
        noisy = True
        projection_notes = [
            *projection_notes,
            f"UNWORKABLE VOLUME: {volume:,.0f} alerts/day is past the {ALERT_VOLUME_CEILING:,.0f}/day "
            "a single rule can sustain in triage. Narrow the logic or raise the threshold before this "
            "goes anywhere near production",
        ]

    tier = _confidence_tier(candidate, result, noisy, reliable)

    return PredictionResult(
        estimated_alert_volume=round(volume, 2),
        confidence_tier=tier,
        notes=_notes(candidate, result, noisy, tier, projection_notes),
        backtest=result,
        projection_basis=basis,
        noisy=noisy,
    )


def backtest(
    candidate: MatchCandidate,
    records: Sequence[LogRecord],
    fingerprint: LogFingerprint,
    *,
    sigma_rule: Any | None = None,
    taxonomy_entry: TaxonomyEntry | None = None,
) -> BacktestResult:
    """Execute the candidate's logic against the sample and count what fires."""
    total = len(records)
    resolver = _build_resolver(candidate, fingerprint)

    try:
        if taxonomy_entry is not None:
            matched = _evaluate_taxonomy(taxonomy_entry, records, resolver)
        elif sigma_rule is not None:
            matched = _evaluate_sigma(sigma_rule, records, resolver)
        else:
            return BacktestResult(
                total_events=total,
                unsupported_reason=(
                    "no detection logic was available to run: the Sigma rule file could not be "
                    "re-read, or the taxonomy entry was not supplied"
                ),
            )
    except _Unsupported as exc:
        return BacktestResult(total_events=total, unsupported_reason=str(exc))
    except Exception as exc:  # noqa: BLE001 - one odd rule must not sink the run
        return BacktestResult(
            total_events=total, unsupported_reason=f"evaluation failed: {type(exc).__name__}: {exc}"
        )

    alerts = len(matched)
    aggregation_note = None
    if taxonomy_entry is not None and isinstance(taxonomy_entry.detection_logic.get("aggregation"), dict):
        alerts, aggregation_note = _apply_aggregation(
            taxonomy_entry.detection_logic["aggregation"], matched, resolver, fingerprint
        )

    return BacktestResult(
        evaluated=True,
        total_events=total,
        matched_events=len(matched),
        alerts=alerts,
        match_rate=round(len(matched) / total, 4) if total else 0.0,
        example_lines=[record.line for record in matched[:5]],
        aggregation_note=aggregation_note,
    )


# ------------------------------------------------------------ field resolution


def _build_resolver(candidate: MatchCandidate, fingerprint: LogFingerprint) -> dict[str, str]:
    """Rule field name -> sample column, using what matching already worked out."""
    resolver = dict(candidate.matched_fields)
    for name, field in fingerprint.resolvable_names().items():
        resolver.setdefault(name, field)
    return resolver


def _resolve(name: str, resolver: dict[str, str]) -> str | None:
    return resolver.get(name) or resolver.get(name.lower())


def _value_of(record: LogRecord, field: str | None) -> str | None:
    if field is None:
        return None
    value = record.fields.get(field)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _blob(record: LogRecord) -> str:
    """The whole event as one string, for Sigma's fieldless keyword search."""
    return " ".join("" if value is None else str(value) for value in record.fields.values())


# --------------------------------------------------------------- Sigma logic


def _evaluate_sigma(rule: Any, records: Sequence[LogRecord], resolver: dict[str, str]) -> list[LogRecord]:
    conditions = getattr(getattr(rule, "detection", None), "parsed_condition", None)
    if not conditions:
        raise _Unsupported("the rule has no parsed condition")

    trees = [condition.parse() for condition in conditions]
    matched: list[LogRecord] = []
    for record in records:
        blob = _blob(record)
        # Multiple conditions in one rule are alternatives.
        if any(_eval_sigma_node(tree, record, blob, resolver) for tree in trees):
            matched.append(record)
    return matched


def _eval_sigma_node(node: Any, record: LogRecord, blob: str, resolver: dict[str, str]) -> bool:
    name = type(node).__name__

    if name in {"ConditionAND", "ConditionOR"}:
        args = node.args
        if name == "ConditionAND":
            return all(_eval_sigma_node(arg, record, blob, resolver) for arg in args)
        return any(_eval_sigma_node(arg, record, blob, resolver) for arg in args)
    if name == "ConditionNOT":
        return not _eval_sigma_node(node.args[0], record, blob, resolver)

    if name == "ConditionFieldEqualsValueExpression":
        column = _resolve(node.field, resolver)
        return _match_sigma_value(node.value, _value_of(record, column), keyword=False)
    if name == "ConditionValueExpression":
        return _match_sigma_value(node.value, blob, keyword=True)

    raise _Unsupported(f"Sigma condition node '{name}' is not implemented")


def _match_sigma_value(value: Any, actual: str | None, *, keyword: bool) -> bool:
    kind = type(value).__name__

    if kind == "SigmaNull":
        return actual is None
    if actual is None:
        return False

    if kind == "SigmaString":
        pattern = _compiled_pattern(_sigma_string_pattern(value))
        return bool(pattern.search(actual) if keyword else pattern.fullmatch(actual))
    if kind in {"SigmaNumber", "SigmaBool"}:
        return str(value).strip().lower() == actual.strip().lower()
    if kind == "SigmaRegularExpression":
        return bool(_compiled_regex(_regex_source(value), _regex_flags(value)).search(actual))
    if kind == "SigmaCIDRExpression":
        return _in_cidr(actual, str(getattr(value, "cidr", "")))
    if kind == "SigmaCompareExpression":
        return _numeric_compare(actual, value)
    if kind == "SigmaExpansion":
        return any(_match_sigma_value(item, actual, keyword=keyword) for item in getattr(value, "values", []))

    raise _Unsupported(f"Sigma value type '{kind}' is not implemented")


def _sigma_string_pattern(value: Any) -> str:
    """Turn a SigmaString's parts into a regex. Non-str parts are wildcards."""
    pieces: list[str] = []
    for part in value.s:
        if isinstance(part, str):
            pieces.append(re.escape(part))
        elif getattr(part, "name", "") == "WILDCARD_SINGLE":
            pieces.append(".")
        else:  # WILDCARD_MULTI
            pieces.append(".*")
    return "".join(pieces)


def _regex_source(value: Any) -> str:
    regexp = getattr(value, "regexp", None)
    if regexp is None:
        raise _Unsupported("regular expression with no pattern")
    if isinstance(regexp, str):
        return regexp
    to_plain = getattr(regexp, "to_plain", None)
    return str(to_plain()) if callable(to_plain) else str(regexp)


def _in_cidr(actual: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(actual) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _numeric_compare(actual: str, value: Any) -> bool:
    operation = getattr(getattr(value, "op", None), "value", None) or str(getattr(value, "op", ""))
    try:
        left = float(actual)
        right = float(str(getattr(value, "number", "")))
    except (TypeError, ValueError):
        return False

    operation = operation.lower()
    if operation in {"gt", ">"}:
        return left > right
    if operation in {"gte", ">="}:
        return left >= right
    if operation in {"lt", "<"}:
        return left < right
    if operation in {"lte", "<="}:
        return left <= right
    raise _Unsupported(f"comparison operator '{operation}' is not implemented")


# ------------------------------------------------------------ taxonomy logic


def _evaluate_taxonomy(
    entry: TaxonomyEntry,
    records: Sequence[LogRecord],
    resolver: dict[str, str],
) -> list[LogRecord]:
    logic = entry.detection_logic
    blocks = {
        name: spec for name, spec in logic.items()
        if name not in _RESERVED_LOGIC_KEYS and isinstance(spec, dict)
    }
    if not blocks:
        raise _Unsupported("the entry has no selection blocks to evaluate")

    expression = str(logic.get("condition") or " and ".join(blocks))
    # An aggregation is expressed after a pipe; per-event matching uses the left side.
    expression = expression.split("|")[0].strip()
    tree = _parse_condition(expression, set(blocks))

    matched: list[LogRecord] = []
    for record in records:
        values = {name: _match_block(spec, record, resolver) for name, spec in blocks.items()}
        if _eval_condition(tree, values):
            matched.append(record)
    return matched


def _parse_condition(expression: str, known: set[str]) -> ast.expression:
    """Parse a boolean expression over block names.

    Walked as an AST rather than evaluated, so only boolean structure over known
    block names can ever run: no attribute access, no calls, nothing executable.
    """
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise _Unsupported(f"condition '{expression}' is not a boolean expression ({exc.msg})") from exc

    for node in ast.walk(tree):
        # ast.Load is the context attached to every Name; it is structure, not code.
        if isinstance(node, (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Not, ast.Load)):
            continue
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            continue
        if isinstance(node, ast.Name):
            if node.id not in known:
                raise _Unsupported(f"condition references unknown block '{node.id}'")
            continue
        raise _Unsupported(f"condition '{expression}' uses an unsupported construct")

    return tree


def _eval_condition(tree: Any, values: dict[str, bool]) -> bool:
    def walk(node: Any) -> bool:
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.BoolOp):
            results = (walk(value) for value in node.values)
            return all(results) if isinstance(node.op, ast.And) else any(results)
        if isinstance(node, ast.UnaryOp):
            return not walk(node.operand)
        if isinstance(node, ast.Name):
            return values[node.id]
        raise _Unsupported("unsupported condition node")

    return walk(tree)


def _match_block(spec: dict[str, Any], record: LogRecord, resolver: dict[str, str]) -> bool:
    """A selection block: AND across its fields, OR across each field's values."""
    for raw_field, expected in spec.items():
        field_name, _, modifier_text = str(raw_field).partition("|")
        modifiers = [modifier for modifier in modifier_text.split("|") if modifier]
        actual = _value_of(record, _resolve(field_name.strip(), resolver))

        candidates = expected if isinstance(expected, list) else [expected]
        results = [_match_scalar(item, actual, modifiers) for item in candidates]
        if not (all(results) if "all" in modifiers else any(results)):
            return False
    return True


def _match_scalar(expected: Any, actual: str | None, modifiers: Sequence[str]) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False

    wanted = str(expected)
    cased = "cased" in modifiers
    haystack = actual if cased else actual.lower()
    needle = wanted if cased else wanted.lower()

    for modifier in modifiers:
        if modifier in {"all", "cased"}:
            continue
        if modifier == "contains":
            return needle in haystack
        if modifier == "startswith":
            return haystack.startswith(needle)
        if modifier == "endswith":
            return haystack.endswith(needle)
        if modifier == "re":
            # Same rule as Sigma: the pattern's own inline flags decide, not ours.
            return bool(_compiled_regex(wanted).search(actual))
        if modifier in {"gt", "gte", "lt", "lte"}:
            return _compare_numbers(actual, wanted, modifier)
        raise _Unsupported(f"field modifier '{modifier}' is not implemented")

    if "*" in needle:
        return bool(re.fullmatch(re.escape(needle).replace(r"\*", ".*"), haystack))
    return haystack == needle


def _compare_numbers(actual: str, expected: str, operation: str) -> bool:
    try:
        left, right = float(actual), float(expected)
    except ValueError:
        return False
    return {
        "gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right
    }[operation]


# --------------------------------------------------------------- aggregation


def _apply_aggregation(
    aggregation: dict[str, Any],
    matched: Sequence[LogRecord],
    resolver: dict[str, str],
    fingerprint: LogFingerprint,
) -> tuple[int, str]:
    """Collapse matching events into the alerts a threshold rule would raise."""
    threshold = int(aggregation.get("count_gte") or aggregation.get("count") or 1)
    group_by = [str(field) for field in aggregation.get("group_by", [])]
    window_seconds = _window_seconds(str(aggregation.get("window", "")))

    timestamp_source = fingerprint.timestamp_source()
    buckets: dict[tuple, int] = defaultdict(int)

    for record in matched:
        key = tuple(_value_of(record, _resolve(field, resolver)) for field in group_by)
        bucket = 0
        if window_seconds and timestamp_source is not None:
            moment = timestamp_source.resolve(record.fields)
            if moment is not None:
                bucket = int(moment.timestamp() // window_seconds)
        buckets[(key, bucket)] += 1

    alerts = sum(1 for count in buckets.values() if count >= threshold)

    detail = f"grouped by {', '.join(group_by) or 'nothing'}, threshold {threshold}"
    if window_seconds and timestamp_source is not None:
        detail += f", tumbling {aggregation.get('window')} windows"
    elif window_seconds:
        detail += ", but no timestamp field was found so the whole sample counted as one window"
    else:
        detail += ", no window declared so the whole sample counted as one"
    note = (
        f"{len(matched)} matching event(s) collapse to {alerts} alert(s): {detail}. "
        "Tumbling windows are an approximation of Elastic's sliding evaluation."
    )
    return alerts, note


def _window_seconds(window: str) -> int:
    text = window.strip().lower()
    if not text or text[-1] not in _WINDOW_UNITS:
        return 0
    try:
        return int(text[:-1]) * _WINDOW_UNITS[text[-1]]
    except ValueError:
        return 0


# ---------------------------------------------------------------- projection


def _sample_span_seconds(records: Sequence[LogRecord], fingerprint: LogFingerprint) -> float | None:
    source = fingerprint.timestamp_source()
    if source is None or not records:
        return None
    moments = [
        moment for moment in (source.resolve(record.fields) for record in records)
        if moment is not None
    ]
    if len(moments) < 2:
        return None
    return (max(moments) - min(moments)).total_seconds()


def _project(
    result: BacktestResult,
    span_seconds: float | None,
    log_rate_per_day: float | None,
) -> tuple[float, str, list[str], bool]:
    """Project alerts per day. The fourth value says whether to believe it.

    A projection is only trustworthy when the measured rate rests on enough
    events, and when either the client stated their production volume or the
    sample covers enough time to extrapolate from.
    """
    notes: list[str] = []

    if not result.evaluated:
        return 0.0, "not projectable", ["the logic could not be executed, so no volume was projected"], False

    enough_events = result.total_events >= MIN_EVENTS_FOR_NOISE

    if log_rate_per_day:
        if not result.total_events:
            return 0.0, "not projectable", ["the sample holds no events to scale from"], False
        volume = (result.alerts / result.total_events) * log_rate_per_day
        notes.append(
            f"scaled from the sample's alert rate to the stated production volume of "
            f"{log_rate_per_day:,.0f} events/day"
        )
        if not enough_events:
            notes.append(
                f"but that rate was measured over only {result.total_events} events, so treat the "
                "figure as an order of magnitude, not a forecast"
            )
        return volume, "client log rate", notes, enough_events

    if span_seconds and span_seconds > 0:
        volume = result.alerts * 86400 / span_seconds
        reliable = enough_events and span_seconds >= RELIABLE_SPAN_SECONDS
        if span_seconds < RELIABLE_SPAN_SECONDS:
            notes.append(
                f"UNRELIABLE: the sample spans only {span_seconds / 60:.0f} minutes, so this daily "
                f"figure is a {86400 / span_seconds:.0f}x extrapolation. Ask the client for a log "
                "rate, or a longer sample, before quoting it"
            )
        elif not enough_events:
            notes.append(
                f"measured over only {result.total_events} events, so treat the figure as an order "
                "of magnitude"
            )
        return volume, "sample time span", notes, reliable

    return 0.0, "not projectable", [
        "no usable timestamps and no stated log rate, so alert volume cannot be projected"
    ], False


# --------------------------------------------------------------------- tiers


def _confidence_tier(
    candidate: MatchCandidate,
    result: BacktestResult,
    noisy: bool,
    projection_reliable: bool,
) -> ConfidenceTier:
    if not result.evaluated or candidate.missing_fields:
        return ConfidenceTier.LOW
    if noisy:
        return ConfidenceTier.LOW
    if result.matched_events == 0:
        # Feasible but unexercised by this data. Not a failure, not a proof.
        return ConfidenceTier.MEDIUM if candidate.confidence >= 0.6 else ConfidenceTier.LOW
    if candidate.confidence >= 0.75 and candidate.field_coverage >= 1.0 and projection_reliable:
        return ConfidenceTier.HIGH
    # High confidence requires knowing what the rule would cost to run. Without a
    # trustworthy volume projection, medium is as far as this can honestly go.
    return ConfidenceTier.MEDIUM


def _notes(
    candidate: MatchCandidate,
    result: BacktestResult,
    noisy: bool,
    tier: ConfidenceTier,
    projection_notes: Sequence[str],
) -> str:
    parts: list[str] = []

    if not result.evaluated:
        parts.append(f"Not backtested: {result.unsupported_reason}")
    else:
        parts.append(
            f"{result.matched_events} of {result.total_events} sample events match "
            f"({result.match_rate:.1%})"
        )
        if result.aggregation_note:
            parts.append(result.aggregation_note)
        if result.matched_events == 0:
            parts.append(
                "Nothing in this sample exercises the rule, so it is feasible but unproven; that is "
                "not evidence the rule is wrong"
            )
        elif result.total_events < MIN_EVENTS_FOR_NOISE:
            parts.append(
                f"Too few events ({result.total_events}) to judge noise; a match rate needs at least "
                f"{MIN_EVENTS_FOR_NOISE} events to mean anything"
            )
        if noisy:
            parts.append(
                f"POTENTIALLY NOISY: matching more than {NOISE_THRESHOLD:.0%} of all events usually "
                "means the logic describes normal traffic. Tune before going live"
            )

    if candidate.missing_fields:
        parts.append(f"Fields absent from the sample: {', '.join(candidate.missing_fields)}")

    parts.extend(projection_notes)
    parts.append(f"Confidence tier {tier.value}")
    return ". ".join(part.strip().rstrip(".") for part in parts if part.strip()) + "."


@lru_cache(maxsize=2048)
def _compiled_pattern(pattern: str) -> re.Pattern[str]:
    """A wildcard pattern derived from a Sigma string.

    Case-insensitive, because that is Sigma's default for plain string values.
    """
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


@lru_cache(maxsize=2048)
def _compiled_regex(pattern: str, flags: int = 0) -> re.Pattern[str]:
    """An author-written regular expression, with only the flags it asked for.

    Sigma's `|re` modifier is case-sensitive unless the pattern says otherwise,
    and `.` is not supposed to cross a newline. Forcing IGNORECASE and DOTALL
    here, as this used to, makes every regex rule quietly match more than its
    author wrote -- the worst kind of error in a tool that estimates alert volume.
    """
    return re.compile(pattern, flags)


def _regex_flags(value: Any) -> int:
    """Translate a SigmaRegularExpression's declared flags into re flags."""
    flags = 0
    for flag in getattr(value, "flags", None) or ():
        name = getattr(flag, "name", str(flag)).upper()
        if "IGNORECASE" in name:
            flags |= re.IGNORECASE
        elif "MULTILINE" in name:
            flags |= re.MULTILINE
        elif "DOTALL" in name:
            flags |= re.DOTALL
    return flags
