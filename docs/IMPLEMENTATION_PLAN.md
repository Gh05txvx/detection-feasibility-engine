# Implementation Plan

Companion to `docs/BLUEPRINT.md` — read that first for design rationale (why each decision was made). This file has the operational detail: schemas, folder structure, and phase-by-phase tasks. Read the section relevant to whatever you're currently building; you don't need all of this loaded to work on any one part.

---

## 1. Architecture recap

```
[Raw Log: CSV / JSON / Syslog / Text]
                │
                ▼
   ┌─────────────────────────────┐
   │ 1. Ingestion & Normalization  │
   └─────────────────────────────┘
                │
                ▼
   ┌─────────────────────────────┐
   │ 2. Field & Schema Profiling  │
   └─────────────────────────────┘
                │
                ▼
   ┌─────────────────────────────┐
   │ 3. Feasibility Matching      │──── Sigma corpus (offline)
   │    Engine                    │──── internal taxonomy (curated)
   └─────────────────────────────┘
                │
        ┌───────┴───────┐
        ▼               ▼
     MATCH           NO MATCH
        │               │
        ▼               ▼
┌───────────────┐ ┌─────────────────────┐
│ 4. Rule Type   │ │ 5. Hypothesis &      │
│    Classifier  │ │    Validation Module │
└───────────────┘ └─────────────────────┘
        │               │
        ▼               │
┌───────────────┐       │
│ 6. Prediction  │       │
│  & Backtest    │       │
└───────────────┘       │
        │               │
        └───────┬───────┘
                ▼
   ┌─────────────────────────────┐
   │ 7. Runbook Generator         │
   └─────────────────────────────┘
                │
                ▼
   ┌─────────────────────────────┐
   │ 8. Human Review Checkpoint   │
   └─────────────────────────────┘
```

Full narrative explanation of every stage: `docs/BLUEPRINT.md` Section 4-5.

---

## 2. Full project structure

```
detection-feasibility-engine/
├── run.bat                          # launcher: venv, start server, open browser (Phase 6+)
├── requirements.txt
├── pyproject.toml
├── CLAUDE.md
├── README.md
├── engine/
│   ├── __init__.py
│   ├── pipeline.py                  # process_log_sample() orchestrator
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── parser.py                 # CSV/JSON/syslog auto-detect + parse
│   │   └── schemas.py                # LogRecord
│   ├── profiling/
│   │   ├── __init__.py
│   │   ├── field_profiler.py         # cardinality, null rate, distribution
│   │   ├── entity_recognition.py     # regex: ip/domain/hash/email/url/port/path
│   │   ├── ecs_gap.py                # ECS compliance check + elastic/integrations lookup
│   │   └── data_classifier.py        # DataCategory classification
│   ├── matching/
│   │   ├── __init__.py
│   │   ├── sigma_matcher.py          # match against local Sigma corpus
│   │   ├── taxonomy_matcher.py       # match against internal taxonomy
│   │   └── candidate.py              # MatchCandidate
│   ├── classification/
│   │   ├── __init__.py
│   │   └── rule_type_classifier.py   # decision table -> ElasticRuleType
│   ├── hypothesis/
│   │   ├── __init__.py
│   │   ├── able.py                   # Hypothesis (Actor/Behavior/Location/Evidence)
│   │   ├── validator.py              # reassess -> baseline -> correlate -> filter -> document
│   │   └── report.py                 # HypothesisReport + rejection report renderer
│   ├── prediction/
│   │   ├── __init__.py
│   │   └── backtest.py               # backtest, volume extrapolation, confidence tier
│   ├── runbook/
│   │   ├── __init__.py
│   │   └── generator.py              # markdown runbook renderer
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── db.py                     # SQLite connection + schema migrations
│   │   ├── taxonomy_store.py         # internal taxonomy CRUD
│   │   └── job_store.py              # job/run history CRUD (Phase 6+)
│   └── web/
│       ├── __init__.py
│       ├── serve.py                  # FastAPI app, binds 127.0.0.1 only
│       ├── routes.py                 # upload / structure / results / history
│       └── templates/
│           ├── base.html
│           ├── upload.html
│           ├── fingerprint.html
│           ├── results.html
│           └── history.html
├── data/                             # gitignored
│   ├── sigma-corpus/                 # cloned SigmaHQ/sigma
│   ├── elastic-integrations/         # cloned elastic/integrations
│   ├── mitre-attack/                 # MITRE ATT&CK STIX bundle
│   └── engine.db                     # SQLite
├── scripts/
│   ├── setup.ps1                     # one-time: venv, deps, clone corpora
│   └── cli.py                        # CLI entrypoint, Phase 0-5
├── docs/
│   ├── BLUEPRINT.md
│   └── IMPLEMENTATION_PLAN.md
└── tests/
    ├── fixtures/                     # sample raw logs (known cases: Fortinet, Cloudflare, CyberArk)
    └── test_*.py
```

### Module → blueprint section map

| Path | Blueprint section |
|---|---|
| `engine/ingestion/` | 5.1 |
| `engine/profiling/` | 5.2 |
| `engine/matching/` | 5.3 |
| `engine/classification/` | 5.4 |
| `engine/hypothesis/` | 5.5 |
| `engine/prediction/` | 5.6 |
| `engine/runbook/` | 5.7 |
| Human review step (no code — a process, not a module) | 5.8 |
| `engine/web/`, `run.bat` | Section 8 |

---

## 3. Data schemas

Formalized from `docs/BLUEPRINT.md` Section 7's illustrative skeleton. Use `pydantic.BaseModel` — FastAPI is built around it, so this gets request/response validation for free once Phase 6 starts.

```python
from enum import Enum
from pydantic import BaseModel


class EntityType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    EMAIL = "email"
    URL = "url"
    PORT = "port"
    FILE_PATH = "file_path"
    PROCESS_NAME = "process_name"
    USER = "user"


class DataCategory(str, Enum):
    NETWORK_LOGS = "network_logs"
    ENDPOINT_DATA = "endpoint_data"
    AUTHENTICATION_LOGS = "authentication_logs"
    APPLICATION_LOGS = "application_logs"
    DNS_LOGS = "dns_logs"
    SYSTEM_LOGS = "system_logs"
    THREAT_INTEL_FEED = "threat_intel_feed"


class FieldProfile(BaseModel):
    field_name: str
    dtype: str
    cardinality: int
    null_rate: float
    entity_type: EntityType | None = None
    is_ecs_compliant: bool
    suggested_ecs_field: str | None = None  # set only when is_ecs_compliant is False


class LogFingerprint(BaseModel):
    profiles: list[FieldProfile]
    inferred_category: str | None = None    # analog to Sigma logsource.category
    inferred_product: str | None = None     # analog to Sigma logsource.product
    data_category: DataCategory | None = None
    official_integration_available: bool = False
    official_integration_name: str | None = None  # e.g. "Fortinet FortiGate Firewall Logs"


class MatchSource(str, Enum):
    SIGMA = "sigma"
    INTERNAL_TAXONOMY = "internal_taxonomy"


class MatchCandidate(BaseModel):
    source: MatchSource
    rule_ref: str
    confidence: float
    mitre_techniques: list[str]


class ElasticRuleType(str, Enum):
    CUSTOM_QUERY = "custom_query"
    EQL = "eql"
    THRESHOLD = "threshold"
    ESQL = "esql"
    INDICATOR_MATCH = "indicator_match"
    NEW_TERMS = "new_terms"
    MACHINE_LEARNING = "machine_learning"


class RuleTypeDecision(BaseModel):
    elastic_type: ElasticRuleType
    reasoning: str


class Hypothesis(BaseModel):
    actor: str        # threat actor type / attack category relevant to this log
    behavior: str      # specific TTP, ideally with a MITRE technique ID
    location: str       # log source / data category, from LogFingerprint
    evidence: str        # field(s) or pattern needed to confirm the behavior


class ValidationCheck(BaseModel):
    name: str            # "reassess_data_patterns" | "confirm_baselines" |
                          # "correlate_threat_intel" | "contextual_filtering"
    passed: bool
    detail: str


class HypothesisReport(BaseModel):
    hypothesis: Hypothesis
    checks: list[ValidationCheck]
    verdict: str                 # "rejected"
    remediation: str | None = None


class ConfidenceTier(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PredictionResult(BaseModel):
    estimated_alert_volume: float
    confidence_tier: ConfidenceTier
    notes: str


class RunbookOutput(BaseModel):
    rule_name: str
    objective: str
    mitre_mapping: list[str]
    match_candidate: MatchCandidate
    rule_type: RuleTypeDecision
    prediction: PredictionResult
    markdown_path: str


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class JobRecord(BaseModel):
    job_id: str
    filename: str
    status: JobStatus
    created_at: str
    result_type: str | None = None   # "runbook" | "rejection_report"
    result_path: str | None = None
```

---

## 4. Phase-by-phase tasks

Work through phases in order. Do not start a phase's tasks before the previous phase's Definition of Done is met — this is deliberate, not overcaution (see `docs/BLUEPRINT.md` Section 2's note on why UI comes last).

### Phase 0 — Seed the knowledge base
**Objective:** establish the local reference data everything else depends on. No engine logic yet.

- [x] Set up `requirements.txt` and venv (fastapi, uvicorn, pandas, pysigma, pysigma-backend-elasticsearch, sigma-cli, jinja2, pydantic, pytest)
- [x] Write `scripts/setup.ps1`: clone `SigmaHQ/sigma` → `data/sigma-corpus/`, clone `elastic/integrations` → `data/elastic-integrations/`, download the MITRE ATT&CK STIX bundle → `data/mitre-attack/`
- [x] Implement `engine/storage/db.py` — SQLite schema for `taxonomy_entries` and `job_runs` (design both now even though `job_runs` isn't used until Phase 6)
- [x] Seed 1-2 internal taxonomy entries manually, porting the existing Cloudflare WAF 15-category pattern into the new schema, as a structural proof
- [x] Manual smoke test: take one known raw log sample, manually trace it to at least one matching Sigma rule

**Definition of done:** one log sample can be profiled and matched (by hand) to at least one Sigma rule.
**Not in scope yet:** no matching/classification code.

**Status: done (2026-08-23).** Write-up and evidence: `docs/phase0-smoke-test.md`. What
landed, and the two decisions that deviate from the text above:

- Corpora: 3144 Sigma rules, 481 integration packages, 51 MB MITRE Enterprise bundle,
  151 MB total in `data/`.
- `elastic/integrations` is a **blobless sparse checkout** (package manifests, field
  definitions, ingest pipelines), not a full clone. A full checkout is several GB and
  cannot complete on Windows at all: some packages ship fixture filenames containing
  `:`, which NTFS rejects. `setup.ps1` documents the `core.protectNTFS` workaround.
- Seed entries are 2 of the Cloudflare WAF taxonomy's 15 categories, written from the
  Cloudflare `firewall_events` field set rather than ported from the original file
  (which was not in this repo). Confirm them against the real taxonomy before relying
  on the detection logic; the remaining 13 categories go in the same seed file.
- Schema is at v2. v2 adds `taxonomy_entries.assumptions` — preconditions an entry's
  logic depends on (normalization ingestion must do, client-specific values to confirm
  at onboarding), which Phase 2 reads as onboarding requirements and Phase 5 carries
  into the runbook.
- Five findings from the smoke test are carried into Phase 1 as requirements; they are
  listed in §9 of the write-up. The load-bearing one: **ingestion must URL-decode query
  strings** — skipping it cost 2 of 5 detections on the test sample.

### Phase 1 — MVP matching
**Objective:** prove ingestion → profiling → Sigma-matching works end to end via CLI.

- [x] `engine/ingestion/parser.py` — CSV/JSON auto-detect + parse → `LogRecord` list
- [x] `engine/profiling/field_profiler.py`, `entity_recognition.py` — per-field stats + entity detection → `FieldProfile` list
- [x] `engine/profiling/ecs_gap.py` — ECS compliance check per field, cross-reference `data/elastic-integrations/` before generating a custom mapping suggestion
- [x] `engine/profiling/data_classifier.py` — `DataCategory` classification
- [x] `engine/matching/sigma_matcher.py` — match `LogFingerprint` against local Sigma corpus `logsource` definitions
- [x] `scripts/cli.py` — `python scripts/cli.py path/to/sample.csv` prints fingerprint + match candidates

**Definition of done:** tested against 3-5 old project log samples; matching results hold up on manual review.
**Not in scope yet:** internal taxonomy matching, rule type classifier, hypothesis module, prediction, web UI.

**Status: code complete, Definition of Done NOT met (2026-08-24).** Every task above
is built and the pipeline runs end to end, but the DoD asks for 3-5 *real* project
samples reviewed by hand, and none were available. It was exercised against three
synthetic fixtures instead (Cloudflare firewall events, FortiGate traffic, Windows
Security logons). **Phase 1 stays open until real samples are run through it.**

What the fixtures showed:

| Sample | Fingerprint | Integration resolved | Candidates |
|---|---|---|---|
| Cloudflare firewall events | webserver / cloudflare / firewall_events | `cloudflare_logpush / firewall_event`, 100% | 12 (incl. the Phase 0 rule) |
| FortiGate traffic | firewall / fortinet_fortigate | `fortinet_fortigate / log`, 68% | 1 |
| Windows Security logons | windows / security | none (grok-based package) | 146 |

Design decisions worth knowing before Phase 2:

- **Corpus indexes are cached.** Parsing 3144 Sigma rules with pySigma takes ~23 s
  and the integrations clone ~45 s, far too slow per run. Both are reduced to
  `data/sigma-index.json` and `data/integration-index.json`, rebuilt only when the
  clone changes (`--rebuild-index` forces it).
- **Integration lookup ranks by F2, not by field-overlap count.** Overlap alone
  rewards verbosity: FortiProxy declares 424 source fields to FortiGate's 272 and
  won a FortiGate sample on vocabulary size alone. Precision fixes it; the product
  name only breaks near-ties.
- **Sigma fields resolve through ECS.** Rules are written against a taxonomy
  (`cs-method`), samples carry vendor names (`ClientRequestMethod`); the bridge is
  the ECS mapping from the official integration, so the Phase 0 hand trace is now
  automatic.
- **An unconfirmable logsource element is treated as a mismatch.** A rule pinning
  `product: windows` is dropped for a sample whose product is unknown, rather than
  guessed into the candidate list.
- `pyyaml` added to `requirements.txt`. Not a new install (pysigma already pulls it)
  but now imported directly, so it is declared.

Carried into later phases:

- The internal taxonomy is seeded but **not yet consulted** — `taxonomy_matcher.py`
  is Phase 3. Until then a sample with no Sigma coverage reports NO MATCH even when
  a taxonomy entry would have matched it.
- Sigma rules whose logsource is generic (`category: firewall`) are thin on the
  ground: the FortiGate sample produced one candidate from 3144 rules. That is the
  coverage gap `docs/BLUEPRINT.md` §10 predicts, and the argument for Phase 3.

### Phase 2 — Hypothesis & rejection module
**Objective:** handle the NO MATCH path with structured ABLE-based reasoning instead of a dead end.

- [x] `engine/hypothesis/able.py` — `Hypothesis` model
- [x] `engine/hypothesis/validator.py` — the 5 validation steps (reassess data/patterns → confirm baselines → correlate local threat intel → contextual filtering → document/report)
- [x] `engine/hypothesis/report.py` — `HypothesisReport` model + markdown rejection-report renderer
- [x] Wire into `scripts/cli.py`: no `MatchCandidate` → run the hypothesis module instead

**Definition of done:** a deliberately field-poor sample produces a rejection report with reasoning that holds up on review, not just "no match."

**Status: done, pending your review of the reasoning (2026-08-24).** `tests/fixtures/minimal_appliance_syslog.csv`
is the deliberately field-poor case: a VPN appliance syslog with four columns
(`timestamp`, `host`, `severity`, `message`). It produces a two-hypothesis rejection
report naming the exact gaps and what to ask the client for. `scripts/cli.py --out
report.md` writes it. Whether the reasoning *holds up* is your call, not mine.

Three schema decisions that depart from §3 above, each for a reason:

- **`ValidationCheck.status` is three-state**, not a boolean. A baseline question
  asked of a behavior that needs no baseline has no answer, and recording it as a
  pass would overstate what was verified. `passed` remains available as a computed
  field and is true for anything that is not a failure.
- **A second verdict, `feasible_no_rule`.** §3 comments `verdict` as always
  `"rejected"`, but when all four checks pass, "rejected" is simply false: the data
  *would* support a rule and only the rule is missing. That verdict points at
  authoring one and encoding it into the internal taxonomy, which is a different
  action from asking the client for more fields.
- **`Hypothesis.evidence_requirements` alongside `evidence: str`.** The plan's
  free-text `evidence` is what a human reads; the reassess check needs the same
  statement in a form it can actually test.

Design notes:

- The report distinguishes "this field is absent" from "this field exists but is
  buried in free text". On the appliance fixture the user and outcome are in
  `message`, so the remediation is a parsing change at ingest, not a request for
  new log data from the client. Those are very different asks.
- Hypotheses come from the data category, per `docs/BLUEPRINT.md` 5.2. An
  unclassified sample gets one placeholder hypothesis whose rejection says the
  source must be identified first, rather than a fabricated guess.
- **A precision fix in `ecs_gap` came out of this phase.** The four-field appliance
  sample resolved to `bbot / asm_intel` (an OSINT scanning tool) purely because
  `timestamp`, `host`, and `severity` are common to hundreds of packages. Field
  matching now requires at least two *distinctive* fields, where distinctive means
  carried by under 5% of data streams. Generic names are no longer evidence.

### Phase 3 — Rule type classifier + internal taxonomy
**Objective:** complete the MATCH path with a proper Elastic rule-type recommendation, and extend matching past Sigma's public coverage.

- [x] `engine/matching/taxonomy_matcher.py` — query the internal taxonomy table
- [x] A minimal taxonomy-authoring workflow (a script is fine for now) — taxonomy needs to grow per project, per `docs/BLUEPRINT.md` Section 3
- [x] `engine/classification/rule_type_classifier.py` — encode the decision table from `docs/BLUEPRINT.md` Section 5.4 as explicit rules, not a model
- [ ] Validate rule-type output against a handful of past manual decisions

**Definition of done:** rule-type recommendations for match candidates are consistent with the decisions an analyst would normally make by hand.

**Status: code complete, Definition of Done NOT met (2026-08-24).** The classifier is
validated against the decision table in `docs/BLUEPRINT.md` 5.4 — all seven rows are
encoded as test cases — but that is validating the encoding, not the outcome. The DoD
asks whether the recommendations match what *your analysts* actually decided on past
projects, and I have none of those cases. **Phase 3 stays open until a handful of real
past decisions are run through it.** Same blocker as Phase 1.

How the classifier works, and why:

- **Capability-first, not type-first.** Each signal identifies what the detection must
  be able to *do* — count events, order them, join to an indicator index — and the
  chosen type is the simplest that provides all of them. This is what the blueprint's
  "use the simplest sufficient type" means operationally, and it stays stable when two
  rows of the table both look applicable. `sequence + count` resolves to ES|QL because
  Threshold cannot order and EQL cannot count.
- **Signals rank by authority:** the taxonomy entry's detection logic (a declared
  `aggregation` block *is* a requirement), then the curator's `suggested_rule_type`,
  then the MITRE technique and sample entity types — which only ever raise
  *alternatives*, never force a type.
- **Indicator Match is reported per sample, not per candidate.** Read literally, row 5
  of the table ("a field holds an entity matchable to threat intel") fires on every rule
  in any log containing an IP. That is a property of the data, so the CLI states it once
  under the fingerprint instead of appending it to every candidate.
- **A taxonomy entry's curated confidence is a ceiling.** A perfect structural match
  scores no higher than the analyst who wrote the entry was willing to claim.

Taxonomy authoring (`python scripts/taxonomy.py`): `template` → edit → `validate` →
`import`, plus `list`, `show`, `export`, `delete`. Import upserts by slug, and `export`
writes the whole taxonomy back in seed-file format so it can be version-controlled or
handed to another engineer. `validate` also lints for things that parse but disappoint:
no `required_fields` (feasibility becomes uncheckable), no MITRE technique (the runbook
gets no ATT&CK mapping), no logsource (the entry matches every sample).

Refactor worth knowing: "which names can this sample answer to" moved onto
`LogFingerprint.resolvable_names()`, since both matchers need the same ECS bridge and it
is a property of the fingerprint rather than of either matcher.

### Phase 4 — Prediction & backtest
**Objective:** estimate rule performance before it's ever created in Kibana, so noisy candidates get flagged early.

- [ ] `engine/prediction/backtest.py` — run candidate rule logic against the raw sample, count matches
- [ ] Volume extrapolation (given an estimated log rate, or derived from the sample's time range)
- [ ] Confidence tier scoring — combine matching confidence, field completeness, and backtest result

**Definition of done:** estimated alert volume isn't wildly off from real deployed rules of a similar type.

### Phase 5 — Runbook generator + workflow integration
**Objective:** produce a review-ready artifact analysts actually use, and make the CLI pipeline standard practice at project kickoff.

- [ ] `engine/runbook/generator.py` — markdown runbook per `docs/BLUEPRINT.md` Section 5.7's field list
- [ ] `engine/pipeline.py` — the orchestrator (`process_log_sample()`) tying ingestion → profiling → matching → classification → hypothesis-or-prediction → runbook together
- [ ] Use in at least one real project, start to handover, still CLI-based

**Definition of done:** used in at least 1 real project, start to handover. Engine is still CLI-only at this point.

### Phase 6 — Local web UI
**Objective:** wrap the now-validated engine with the UI layer described in `docs/BLUEPRINT.md` Section 8. Only start this once Phase 5's Definition of Done is met.

- [ ] `engine/storage/job_store.py` — `job_runs` CRUD
- [ ] `engine/web/serve.py` — FastAPI app, bound to `127.0.0.1` only
- [ ] `engine/web/routes.py` — upload / structure / results / history routes
- [ ] Jinja2 + htmx templates for the 4-page flow (Section 8.4)
- [ ] `run.bat` — launcher with venv activation, port check, auto browser-open

**Definition of done:** a teammate can use the tool without knowing how to run a Python script — double-click the launcher only.
