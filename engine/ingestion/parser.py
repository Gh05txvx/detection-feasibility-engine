"""Parse a raw log sample into LogRecords (docs/BLUEPRINT.md 5.1).

Handles the two input scenarios the engine exists for: a pre-onboarding sample
from the client (CSV/JSON/JSONL), and an export of a live Elastic index whose
fields are not ECS-normalized yet (an Elasticsearch ``_search`` response).

Two normalizations happen here, both deliberate:

* **Nested objects are flattened to dotted keys** so an ES ``_source`` and a flat
  CSV profile the same way.
* **URL-encoded values are decoded.** Measured on the Phase 0 fixture, skipping
  this costs 2 of 5 SQL injection detections: ``+`` stands in for a space, so
  ``\\s`` in a detection pattern stops matching. See docs/phase0-smoke-test.md §9.
  The pre-decode text is preserved in ``LogRecord.raw_fields``.
"""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import unquote, unquote_plus

from engine.ingestion.schemas import LogRecord, ParsedSample, SampleFormat

# Encodings tried in order. Windows-sourced exports are frequently cp1252, and
# failing on one stray byte would be a poor trade for a triage tool.
_ENCODINGS = ("utf-8-sig", "cp1252")

_MAX_PROBLEMS = 20
_SNIFF_BYTES = 65_536

# Field names that signal a URL component, and therefore a value worth decoding.
_URL_FIELD_HINT = re.compile(r"(query|uri|url|path|referer|referrer)", re.IGNORECASE)
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_QUERY_FIELD_HINT = re.compile(r"query", re.IGNORECASE)


class ParseError(Exception):
    """The sample could not be parsed at all."""


def parse(path: str | Path, *, limit: int | None = None) -> ParsedSample:
    """Parse a sample file, auto-detecting its format.

    ``limit`` caps how many records are read, for a quick look at a large export.
    """
    path = Path(path)
    if not path.exists():
        raise ParseError(f"sample not found: {path}")
    if limit is not None and limit < 1:
        raise ParseError(f"limit must be at least 1, got {limit}")

    text, encoding = _read_text(path)
    if not text.strip():
        raise ParseError(f"sample is empty: {path}")

    sample_format = detect_format(path, text)
    if sample_format is SampleFormat.CSV:
        sample = _parse_csv(path, text, encoding, limit)
    else:
        sample = _parse_json_like(path, text, encoding, sample_format, limit)

    # A file where every record failed to parse is a failed ingest, not a sample
    # with nothing in it. Reporting success would send an empty fingerprint all
    # the way through to a rejection report about a file nobody could read.
    if not sample.records and not sample.truncated:
        detail = "; ".join(sample.problems[:3]) or "it has structure but no data rows"
        raise ParseError(f"{path}: no records could be parsed ({detail})")

    return sample


def detect_format(path: Path, text: str) -> SampleFormat:
    """Decide the format from the content, using the extension only to break ties."""
    stripped = text.lstrip()
    first_char = stripped[:1]
    suffix = path.suffix.lower()

    if first_char == "[":
        return SampleFormat.JSON
    if first_char == "{":
        # One object per line is JSONL; a single spanning object is JSON.
        lines = [line for line in stripped.splitlines() if line.strip()]
        if len(lines) > 1 and all(line.lstrip().startswith("{") for line in lines[:5]):
            return SampleFormat.JSONL
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return SampleFormat.JSONL
        return SampleFormat.ELASTIC_RESPONSE if _is_elastic_response(payload) else SampleFormat.JSON
    if suffix in {".json", ".ndjson", ".jsonl"}:
        return SampleFormat.JSONL
    return SampleFormat.CSV


def _read_text(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    for encoding in _ENCODINGS:
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    # Last resort: never fail ingestion over an undecodable byte, but say so.
    return raw.decode("utf-8", errors="replace"), "utf-8 (with replacements)"


def _is_elastic_response(payload: Any) -> bool:
    return (
        isinstance(payload, dict)
        and isinstance(payload.get("hits"), dict)
        and isinstance(payload["hits"].get("hits"), list)
    )


# --------------------------------------------------------------------------- CSV


def _parse_csv(path: Path, text: str, encoding: str, limit: int | None) -> ParsedSample:
    delimiter = _sniff_delimiter(text)
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter=delimiter)
    if not reader.fieldnames:
        raise ParseError(f"no header row found in {path}")

    records: list[LogRecord] = []
    problems: list[str] = []
    truncated = False

    # Two columns with the same header collapse into one in a dict, silently
    # discarding the first one's values. Rename instead, and say so.
    header, renamed = _dedupe_headers(reader.fieldnames)
    reader.fieldnames = header
    for note in renamed:
        _note(problems, f"duplicate header column {note}")

    for offset, row in enumerate(reader):
        if limit is not None and len(records) >= limit:
            truncated = True
            break
        # csv.DictReader parks surplus values under None when a row is too long.
        if None in row:
            _note(problems, f"line {offset + 2}: more values than header columns, extras dropped")
            row.pop(None, None)
        records.append(_build_record(offset + 2, row))

    return ParsedSample(
        path=str(path),
        format=SampleFormat.CSV,
        encoding=encoding,
        delimiter=delimiter,
        records=records,
        field_names=_ordered_field_names(records, reader.fieldnames),
        problems=problems,
        truncated=truncated,
    )


def _dedupe_headers(fieldnames: Sequence[str | None]) -> tuple[list[str], list[str]]:
    """Make every column name unique and non-empty, reporting what was renamed."""
    seen: dict[str, int] = {}
    header: list[str] = []
    renamed: list[str] = []

    for index, raw in enumerate(fieldnames):
        name = (raw or "").strip() or f"column_{index + 1}"
        if name in seen:
            seen[name] += 1
            unique = f"{name}__{seen[name]}"
            renamed.append(f"{name!r} at position {index + 1} kept as {unique!r}")
            name = unique
        else:
            seen[name] = 1
        header.append(name)

    return header, renamed


def _sniff_delimiter(text: str) -> str:
    try:
        return csv.Sniffer().sniff(text[:_SNIFF_BYTES], delimiters=",;\t|").delimiter
    except csv.Error:
        # Sniffer gives up on single-column files and on quoted payloads full of
        # punctuation. Comma is the right guess for the exports we see.
        return ","


# -------------------------------------------------------------------- JSON-like


def _parse_json_like(
    path: Path,
    text: str,
    encoding: str,
    sample_format: SampleFormat,
    limit: int | None,
) -> ParsedSample:
    if sample_format is SampleFormat.JSONL:
        rows, problems = _read_jsonl(text)
    else:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"{path}: invalid JSON ({exc})") from exc
        rows, problems = _rows_from_json(payload)

    truncated = False
    if limit is not None and len(rows) > limit:
        rows = rows[:limit]
        truncated = True

    records = [_build_record(index, row) for index, row in rows]
    return ParsedSample(
        path=str(path),
        format=sample_format,
        encoding=encoding,
        records=records,
        field_names=_ordered_field_names(records, None),
        problems=problems,
        truncated=truncated,
    )


def _read_jsonl(text: str) -> tuple[list[tuple[int, dict[str, Any]]], list[str]]:
    rows: list[tuple[int, dict[str, Any]]] = []
    problems: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            _note(problems, f"line {number}: invalid JSON ({exc.msg})")
            continue
        if isinstance(payload, dict):
            rows.append((number, payload))
        else:
            _note(problems, f"line {number}: expected an object, got {type(payload).__name__}")
    return rows, problems


def _rows_from_json(payload: Any) -> tuple[list[tuple[int, dict[str, Any]]], list[str]]:
    problems: list[str] = []

    if _is_elastic_response(payload):
        # Prefer _source; fall back to fields, which is what a search with
        # `"_source": false` and a fields list returns.
        rows = []
        for index, hit in enumerate(payload["hits"]["hits"], start=1):
            body = hit.get("_source") or hit.get("fields") or {}
            if isinstance(body, dict):
                rows.append((index, body))
            else:
                _note(problems, f"hit {index}: unexpected _source type {type(body).__name__}")
        return rows, problems

    if isinstance(payload, list):
        rows = []
        for index, item in enumerate(payload, start=1):
            if isinstance(item, dict):
                rows.append((index, item))
            else:
                _note(problems, f"item {index}: expected an object, got {type(item).__name__}")
        return rows, problems

    if isinstance(payload, dict):
        # A single object wrapping one list of events, e.g. {"events": [...]}.
        lists = [value for value in payload.values() if isinstance(value, list)]
        if len(lists) == 1 and all(isinstance(item, dict) for item in lists[0]):
            return [(index, item) for index, item in enumerate(lists[0], start=1)], problems
        return [(1, payload)], problems

    raise ParseError(f"unsupported JSON top-level type: {type(payload).__name__}")


# ---------------------------------------------------------------- normalization


def _build_record(line: int, row: dict[str, Any]) -> LogRecord:
    flat = _flatten(row)
    fields: dict[str, Any] = {}
    raw_fields: dict[str, str] = {}

    for name, value in flat.items():
        decoded = _decode_url_value(name, value)
        if decoded is None:
            fields[name] = value
        else:
            fields[name] = decoded
            raw_fields[name] = value

    return LogRecord(line=line, fields=fields, raw_fields=raw_fields)


def _flatten(obj: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested objects to dotted keys, the shape ECS field names use."""
    flat: dict[str, Any] = {}
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and value:
            flat.update(_flatten(value, f"{name}."))
        elif isinstance(value, list):
            # Scalar lists read better joined; anything nested keeps its JSON so
            # no information is lost before profiling sees it.
            if all(not isinstance(item, (dict, list)) for item in value):
                flat[name] = ", ".join("" if item is None else str(item) for item in value)
            else:
                flat[name] = json.dumps(value, ensure_ascii=False)
        else:
            flat[name] = value
    return flat


def _decode_url_value(name: str, value: Any) -> str | None:
    """Return the URL-decoded value, or None when decoding does not apply.

    Returns None when decoding changes nothing, so ``raw_fields`` stays empty
    for ordinary logs.

    The `+`-means-space rule is the dangerous one, because it rewrites a
    character that is perfectly legal unencoded. It is applied only when the
    value is demonstrably a query string: it starts with `?`, or it is a
    query-ish field that also carries a percent escape. Without that guard, a
    database audit log with a `query` column turns `SELECT a+b` into
    `SELECT a b` and every later stage sees the corrupted text.
    """
    if not isinstance(value, str) or not value:
        return None

    has_escape = bool(_PERCENT_ESCAPE.search(value))
    if not _URL_FIELD_HINT.search(name) and not has_escape:
        return None

    is_query_string = value.startswith("?") or (has_escape and bool(_QUERY_FIELD_HINT.search(name)))
    decoded = unquote_plus(value) if is_query_string else unquote(value)

    return decoded if decoded != value else None


def _ordered_field_names(records: Iterable[LogRecord], header: Sequence[str] | None) -> list[str]:
    """Field names in first-seen order, starting from the CSV header if there is one."""
    ordered: dict[str, None] = {}
    for name in header or ():
        if name is not None:
            ordered[name] = None
    for record in records:
        for name in record.fields:
            ordered.setdefault(name, None)
    return list(ordered)


def _note(problems: list[str], message: str) -> None:
    if len(problems) < _MAX_PROBLEMS:
        problems.append(message)
    elif len(problems) == _MAX_PROBLEMS:
        problems.append(f"... further problems suppressed after {_MAX_PROBLEMS}")
