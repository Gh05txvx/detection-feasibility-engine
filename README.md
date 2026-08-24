# Detection Feasibility & Rule Recommendation Engine

An offline tool for the build phase of a SIEM implementation. Give it a raw log
sample and it tells you which Elastic Security detection rules could realistically
be built from that data — or, when none can, exactly what is missing and what to
ask the client for.

It exists because the same work happens by hand on every IMS project: read the
client's log sample, work out which fields matter, decide which detection use
cases are feasible, and put a realistic list in the SOW. That is slow, depends on
who happens to be doing it, and does not scale across parallel projects.

**Everything runs locally.** No log content, profiling output, or match result
ever leaves the machine.

---

## What it produces

Two possible outcomes, and the second one is the point as much as the first.

**MATCH** — ranked rule candidates, each with a recommended Elastic rule type, a
backtest against the sample, a projected alert volume, and a draft runbook ending
at a review checklist.

```
  1. [0.80] Cloudflare WAF - SQL injection attempt against public web application
      internal:cloudflare-waf-sqli   source=internal_taxonomy
      mitre: T1190
      rule type: custom_query
        why: Simple field match satisfiable within one event, so custom_query is
             the simplest sufficient type.
      backtest: 5/37 events match (13.5%)  ->  ~718.8 alerts/day   [tier: medium]
        UNRELIABLE: the sample spans only 10 minutes, so this daily figure is a
        144x extrapolation. Ask the client for a log rate before quoting it.
```

**NO MATCH** — a structured rejection report, not a dead end. Hypotheses in ABLE
form, each run through four validation steps, and a deduplicated list of
onboarding requirements you can take to the client.

```
Reassess data & patterns   FAIL
  Missing required evidence: outcome or status, user identity. The sample does
  carry a free-text field ('message') which may hold these values unparsed;
  extracting them at ingest would satisfy this check without new log data.

Correlate with local intel  pass
  T1543 is codified locally: 51 Sigma rules. None of them target this log
  source, which is why matching found nothing: the behavior is well understood,
  just not from this telemetry.

Onboarding requirements
  1. outcome or status
  2. user identity
```

Both paths end at a human review step. Nothing is ever written to Kibana.

---

## Non-negotiables

These are constraints, not preferences. They are enforced in code and covered by
tests.

| | |
|---|---|
| **Fully offline** | The only network activity is the one-time corpus clone during setup. No telemetry, no analytics, no AI API. |
| **Deterministic matching** | No LLM anywhere in ingestion, profiling, matching, classification, or hypothesis logic. Every decision traces to a schema, pattern, or taxonomy entry. |
| **Loopback only** | The web server binds `127.0.0.1`. There is no `--host` argument, and a test fails if a non-loopback bind is ever introduced. |
| **No auto-deploy** | Every output ends at analyst review. The engine never writes a rule to Elastic. |
| **Explainable** | Every match *and* every rejection records its reasoning. A confidence number on its own is not an answer. |

---

## How it works

```
[Raw log: CSV / JSON / JSONL / Elasticsearch _search export]
        |
        v
  1. Ingestion            format detection, nested flattening, URL decoding
        |
        v
  2. Profiling            field stats, entity recognition, log source
        |                 classification, ECS gap analysis
        v
  3. Matching             Sigma corpus  +  internal taxonomy   (in parallel)
        |
    +---+---------------------------+
    |                               |
  MATCH                        NO MATCH
    |                               |
    v                               v
  4. Rule type classifier      5. ABLE hypothesis + validation
    |                               |
    v                               |
  6. Backtest & volume              |
    |                               |
    +---------------+---------------+
                    v
        7. Runbook  /  Rejection report
                    v
        8. Human review checkpoint
```

Two details worth knowing up front:

- **Sigma rules are written against a taxonomy, not against your fields.** A rule
  wants `cs-method`; your sample has `ClientRequestMethod`. The bridge is ECS,
  read out of the official Elastic integration's own ingest pipeline. The engine
  resolves the integration by *data stream field overlap*, never by vendor name —
  `cloudflare` and `cloudflare_logpush` are both "Cloudflare" and only one of them
  matches a firewall-events sample.

- **Alert volume is not event count.** A threshold rule needing 20 failed logins
  produces one alert, not twenty. Aggregated candidates are bucketed by their own
  group-by and window before anything is counted, and every projection is labelled
  with whether it can be trusted.

---

## Getting started

Requires Python 3.11+ and git on PATH. Windows is the primary target.

```powershell
git clone https://github.com/Gh05txvx/detection-feasibility-engine.git
cd detection-feasibility-engine
scripts\setup.ps1
```

One-time: creates `.venv`, installs dependencies, and clones the reference
corpora into `data/`. Roughly 150 MB and a few minutes. Safe to re-run; it
refreshes rather than re-clones.

| Corpus | Contents |
|---|---|
| `SigmaHQ/sigma` | 3144 detection rules with their MITRE mappings |
| `elastic/integrations` | 481 packages — the official vendor-to-ECS field mappings |
| MITRE ATT&CK | Enterprise STIX bundle |

`elastic/integrations` is a blobless sparse checkout of the manifests, field
definitions, and ingest pipelines. A full checkout is several GB and *cannot
complete on Windows at all*: some packages ship fixture filenames containing `:`.

---

## Usage

### Command line

```powershell
python scripts\cli.py tests\fixtures\cloudflare_waf_firewall_events.csv
```

Useful flags:

| Flag | Purpose |
|---|---|
| `--top N` | How many candidates to show, backtest, and write runbooks for (default 10) |
| `--log-rate N` | Production volume in events/day. Without it, alert volume is extrapolated from the sample's own time span, which is unreliable for short samples |
| `--runbook-dir DIR` | Write a draft runbook per candidate |
| `--out FILE` | Write the rejection report markdown |
| `--min-confidence N` | Confidence floor for candidates (default 0.4) |
| `--json` | Machine-readable output instead of the report |
| `--limit N` | Read only the first N records |
| `--rebuild-index` | Force a rebuild of the cached corpus indexes |

The first run after a corpus refresh rebuilds both indexes and takes about a
minute; after that they are cached in `data/`.

### Web UI

```
run.bat
```

Starts the local server and opens a browser at `http://127.0.0.1:8765`. Four
pages: upload, structure & fingerprint, matching results, history. Runs survive a
restart. If the port is already in use, the launcher assumes an instance is
already running and points the browser at it.

### Internal taxonomy

The half of matching that Sigma does not reach: proprietary apps, custom APIs,
niche vendors. It is meant to grow one project at a time.

```powershell
python scripts\taxonomy.py template > new-entry.json   # fill it in
python scripts\taxonomy.py validate new-entry.json     # lint before importing
python scripts\taxonomy.py import new-entry.json       # upserts by slug
python scripts\taxonomy.py list
python scripts\taxonomy.py export scripts\seeds\internal_taxonomy.json
```

`validate` also warns about entries that parse but will disappoint: no
`required_fields` (feasibility becomes uncheckable), no MITRE technique (the
runbook gets no ATT&CK mapping), no logsource (the entry matches every sample).

---

## Project status

All seven phases are built and 225 tests pass. **Four Definitions of Done are
still open, and every one of them needs real project data rather than more code.**

| Phase | Code | Definition of done |
|---|---|---|
| 0 — Seed the knowledge base | done | **met** |
| 1 — MVP matching | done | needs 3–5 real project samples reviewed by hand |
| 2 — Hypothesis & rejection | done | **met**, pending your review of the reasoning |
| 3 — Rule type + taxonomy | done | needs a handful of past manual analyst decisions to compare against |
| 4 — Prediction & backtest | done | needs live rules of a similar type to compare volume against |
| 5 — Runbook + orchestrator | done | needs one real project, start to handover |
| 6 — Local web UI | done | verified mechanically; "a teammate can use it" needs a teammate |

Read that table before trusting any output. The engine has been validated against
five synthetic fixtures covering Cloudflare WAF, FortiGate traffic, Windows
Security, IIS/W3C access logs, and a deliberately field-poor appliance syslog. It
has not yet been run against a real client sample.

The honest ceiling, from `docs/BLUEPRINT.md` §10: this is heuristic matching over
a curated knowledge base. For proprietary or unusual log sources it will often say
"no automatic match", and that is not the same as "not detectable".

---

## Layout

```
engine/
  ingestion/      raw log -> LogRecord
  profiling/      field stats, entity recognition, ECS gap, log source classification
  matching/       Sigma corpus + internal taxonomy
  classification/ Elastic rule type decision table
  hypothesis/     ABLE hypothesis + validation, for the no-match path
  prediction/     backtest, alert volume, confidence tiers
  runbook/        markdown runbook generation
  storage/        SQLite: taxonomy + job history
  web/            FastAPI routes, Jinja2 + htmx templates
  pipeline.py     process_log_sample() — the single entry point
scripts/
  setup.ps1       one-time setup
  cli.py          command line entry point
  taxonomy.py     taxonomy authoring
data/             cloned corpora, engine.db, cached indexes — gitignored
tests/fixtures/   five sample log formats
docs/
  BLUEPRINT.md            design rationale, in full
  IMPLEMENTATION_PLAN.md  schemas, phase checklists, and what each phase decided
  phase0-smoke-test.md    the original hand trace, kept as evidence
```

`pipeline.process_log_sample()` is the only orchestration in the codebase. The
CLI and the web layer both call it; neither reimplements the flow.

## Tests

```powershell
pytest
```

225 tests. Corpus-dependent tests skip themselves when the clones are absent, so
the suite runs on a fresh checkout.

## Stack

Python 3.11+ · pySigma + pySigma-backend-elasticsearch · pandas · SQLite ·
FastAPI + Uvicorn · Jinja2 + htmx (vendored locally, no CDN) · pytest

No npm, no build step.

---

*Internal tool. Log samples are client data and must not reach this repository.
`data/` is gitignored, and so is everything under `tests/fixtures/` except the
five synthetic fixtures, which are re-included by name — drop a real sample in
there and git will ignore it by default rather than because someone remembered
to. A private repo is not the same as a safe one.*
