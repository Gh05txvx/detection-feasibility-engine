# CLAUDE.md

Instructions for Claude Code working in this repository. Read this file fully before writing or modifying any code.

## Project

**Detection Feasibility & Rule Recommendation Engine** — an offline, local tool for IMS (SIEM implementation) work. Takes a raw log sample (a pre-onboarding client sample, or an Elastic index export that isn't ECS-normalized yet) and outputs either a candidate Elastic Security detection rule with a ready-to-review runbook, or a structured rejection report explaining why a rule isn't feasible yet. Used during the build/pre-implementation phase of SIEM projects to speed up log-to-rule feasibility assessment.

Full design rationale: `docs/BLUEPRINT.md`. Detailed schemas, folder structure, and phase-by-phase tasks: `docs/IMPLEMENTATION_PLAN.md`. This file is deliberately short — read the two docs above before working on anything non-trivial.

## Non-negotiables

- **IMPORTANT — fully offline.** No raw log content, profiling output, or match result ever leaves the local machine. No calls to any external API, including logging/telemetry/analytics SDKs. The only network activity allowed is the one-time local clone of reference corpora (SigmaHQ/sigma, elastic/integrations, MITRE ATT&CK STIX) during setup, and the local web server on `127.0.0.1`.
- **IMPORTANT — matching stays deterministic.** No LLM/AI API call anywhere in ingestion, profiling, matching, classification, or hypothesis logic. If a task seems to need one, stop and ask — don't substitute a model call for the schema/pattern/taxonomy approach described in `docs/BLUEPRINT.md`.
- Web server binds to `127.0.0.1` only. Never `0.0.0.0`.
- No rule is ever auto-deployed to Kibana. Every output — runbook or rejection report — ends at a human review step, never at a direct write to Elastic.
- Build order matters: engine core (CLI-usable, Phases 0-5) before the web UI (Phase 6). Don't start UI work while core matching/classification logic is still unstable — see `docs/IMPLEMENTATION_PLAN.md` for phase definitions of done.
- Don't add a dependency outside the Tech Stack list below without flagging it first.

## Tech stack

- Python 3.11+
- Web: FastAPI + Uvicorn
- Frontend: Jinja2 + htmx — no React/Vue, no build step, no npm
- Data: pandas (profiling), SQLite (taxonomy + job history)
- Detection matching: pySigma + sigma-cli + pySigma-backend-elasticsearch
- Local reference corpora (cloned once, never called over network at runtime): `SigmaHQ/sigma`, `elastic/integrations`, MITRE ATT&CK STIX bundle

## Project structure

```
engine/
  ingestion/        # raw log parsing -> LogRecord
  profiling/         # field profiling, entity recognition, ECS gap analysis
  matching/           # Sigma corpus + internal taxonomy matching
  classification/      # Elastic rule type decision logic
  hypothesis/           # ABLE hypothesis + validation, for the no-match path
  prediction/            # backtest + confidence scoring
  runbook/                # markdown runbook generation
  storage/                 # SQLite: taxonomy, job history
  web/                       # FastAPI routes + Jinja2/htmx templates
  pipeline.py                 # orchestrator tying the modules together
scripts/
  cli.py             # CLI entrypoint - use this until Phase 6
  setup.ps1           # one-time: venv, deps, clone reference corpora
data/                  # cloned corpora + engine.db - gitignored
docs/
  BLUEPRINT.md
  IMPLEMENTATION_PLAN.md
run.bat
```

See `docs/IMPLEMENTATION_PLAN.md` for what goes in each module file, and its module -> blueprint section map.

## Commands

```
scripts\setup.ps1                          # one-time setup: venv, deps, clone corpora
python scripts\cli.py path\to\sample.csv    # run engine against one sample (Phase 0-5)
python scripts\taxonomy.py list             # author/inspect the internal taxonomy
run.bat                                     # launch local web UI (Phase 6 onward)
pytest                                      # run tests
```

## Current phase

Check `docs/IMPLEMENTATION_PLAN.md` for the phase checklist and update it as tasks complete. Don't jump ahead to a later phase's tasks before the current phase's Definition of Done is met.

## When in doubt

Check `docs/BLUEPRINT.md` and `docs/IMPLEMENTATION_PLAN.md` first. If a decision genuinely isn't covered there, stop and ask rather than improvising a new pattern.
