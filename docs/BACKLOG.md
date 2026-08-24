# Backlog

Everything outstanding, as of 2026-08-24. All seven phases are built and 229 tests
pass; what is left is mostly validation that needs real project data, plus a short
list of engineering work that protects that validation.

`docs/IMPLEMENTATION_PLAN.md` holds the per-phase detail and the decisions already
made. This file is the queue.

**Owner** is who can actually do the item: **eng** = can be done from the code,
**you** = needs the team's data, decisions, or judgement, **both** = a working
session.

---

## 1. Before the real-data testing starts

Small, and each one exists to stop the validation work producing a wrong answer or
wasting a review cycle. Worth clearing first.

| # | Task | Owner | Size |
|---|---|---|---|
| 1.1 | ~~**Staleness banner.**~~ **Done 2026-08-24.** `engine/web/staleness.py` fingerprints the `.py` files under `engine/` when the app is built and rechecks at most every 2 seconds. When they differ, every page carries a banner naming the fix. Registered as a Jinja global rather than passed per route, since a warning that only shows on the pages someone remembered to wire it into is not a warning. `base.html` calls it behind `is defined`, so a server predating the global still renders — the banner must not break the very servers it exists to flag. | eng | done |
| 1.2 | ~~**Clean up orphaned jobs at startup.**~~ **Done 2026-08-24.** `job_store.fail_orphaned()` runs when the app is built and fails any run still at `queued` or `running`, since the only process that could ever have finished them is the one that died. The reason says to upload the sample again, and the status page stops polling. | eng | done |
| 1.3 | ~~**Confirm the seeded taxonomy against the real Cloudflare WAF file.**~~ **Done 2026-08-24.** Checked against the team's own material. Findings below. | both | done |

### 1.3 — what the confirmation found

Category names are now known and recorded in the seed file's `source`:
**PathTraversal, KnownCVE_Signature, SSRF, NoSQLi, OpenRedirect, SensitivePathAccess,
XSS, SQLi, RCE_CommandInjection**. Those nine are the ones that fired in the single
client dataset available; `docs/BLUEPRINT.md` refers to fifteen, so six are not
represented there and are still unknown here.

Three corrections came out of it:

- **`cloudflare-waf-sqli` maps to a real category**, `SQLi`. But the taxonomy treats
  **`NoSQLi` as a separate category**, and this entry's regex is SQL-keyword based, so
  it would not catch operator-syntax injection inside JSON. Recorded on the entry as a
  deliberate boundary rather than left as an accidental gap.
- **`cloudflare-waf-credential-stuffing` matches nothing in the taxonomy.** All nine
  observed categories are payload-pattern web attacks; there is no brute-force or
  credential-stuffing category. It was written as a second structural example to
  exercise the threshold rule type. Its `source_project` now says *proposed, not yet in
  the in-house taxonomy*, so nobody reads it as codified team knowledge.
- **Two deployment constraints were missing and are now assumptions on the entry.** The
  team's own Cloudflare rules match `http.request.uri`, path and query combined, while
  this entry keys on `ClientRequestPath` and `ClientRequestQuery` separately as Logpush
  delivers them — fine for log analysis, but the fields must be joined if the logic
  becomes a custom rule. And Cloudflare's `matches` operator is Enterprise-plan only,
  on an RE2 engine with no backreferences or lookaround. This pattern uses neither, so
  it ports as written; a future one might not.

One thing worth confirming when convenient: the entry's `Action` list includes `log`,
on the reasoning that a WAF in log-only mode still evidences the attempt. That turns
out to match the team's documented rollout practice — new custom rules run in Log for
several days before Block — so it is aligned, not accidental.
| 1.4 | **Confirm the WAF `RuleID` values.** `cloudflare-waf-sqli` scopes its WAF branch to rule ID `100015`, taken from the synthetic fixture. Real managed-rule IDs are ruleset-specific and must be checked against a client's WAF config. | you | S |
| 1.5 | ~~**Download a single hypothesis as markdown.**~~ **Done 2026-08-24.** Every hypothesis card has its own **Download this hypothesis** button, alongside the whole-report download. See below for what was built. | eng | done |

### 1.5 — one card, one markdown file

Both outcomes on the results page already render as cards: match candidates as
candidate cards, each with its own **Download draft runbook** button, and
hypotheses on the no-match path as cards carrying the ABLE block, the four
validation checks, the verdict, and the remediation.

What is missing is the second half of that symmetry. A match candidate exports on
its own; a hypothesis does not — the only download is the whole report, every
hypothesis in one file.

That matters for the work about to start. The artifact you hand a client is *one*
onboarding ask, backed by the reasoning behind it. Sending a five-hypothesis report
so they can find the relevant page is a worse deliverable, and editing one out by
hand before sending it is worse still.

Built:

- `render_hypothesis_markdown(report, index)` produces a file that stands alone
  when it arrives detached from everything around it: sample, log source, sample
  size, the "no automatic match is not the same as not detectable" framing, the
  ABLE block, the four checks, the remediation, what it needs, and the review
  closing. On the appliance fixture that is 2.4 kB against 5.1 kB for the whole
  report, and it contains nothing about the hypothesis it was not asked for.
- `GET /jobs/{job_id}/hypothesis/{index}`, mirroring `/runbook/{index}` including
  its bounds check, serving `text/markdown` as an attachment. All three download
  routes now go through one helper, so they agree on type and disposition.
- Filenames come from the behaviour —
  `rejection-creation-or-modification-of-a-service-scheduled-task-or-star.md` —
  so a folder of them can be read without opening each one.
- **Sample-wide ingest asks travel with each hypothesis.** A split `date`/`time`
  is the source's problem, not one hypothesis's, so `RejectionReport.ingest_requirements`
  is shared by the combined report and every single-hypothesis export rather than
  living only in the aggregate.

## 2. Closing the four open Definitions of Done

This is the critical path. None of it can be substituted with more code.

| # | Task | Owner | Size |
|---|---|---|---|
| 2.1 | **Phase 1 DoD — run 3–5 real project samples** through `scripts/cli.py` and review whether the matching results hold up. This is the one that matters most: it tells us whether the whole approach works on real logs rather than on fixtures built for the purpose. | both | M |
| 2.2 | **Phase 3 DoD — validate the rule-type classifier** against a handful of rule-type decisions analysts actually made on past projects. All seven rows of the blueprint's decision table are encoded as tests, but that validates the encoding, not the outcome. | both | M |
| 2.3 | **Phase 4 DoD — compare projected alert volume** against live rules of a similar type that are already deployed. Needs the real production log rate per source; without `--log-rate` the projection is an extrapolation from the sample's own span and says so. | you | M |
| 2.4 | **Phase 5 DoD — use the engine on one real project**, start to handover, still CLI-based. The end-to-end test of whether it saves time or adds a step. | you | L |
| 2.5 | **Phase 2 review — read a rejection report properly.** The reasoning is generated and the DoD is technically met; whether it *holds up* is a judgement only an analyst can make. Start with `tests/fixtures/minimal_appliance_syslog.csv`. | you | S |
| 2.6 | **Phase 6 review — have a teammate use the web UI** without being told how. Verified mechanically only. | you | S |

## 3. Coverage, driven by what section 2 finds

Do not do these speculatively. Each should be triggered by a real sample that the
engine handled badly.

| # | Task | Owner | Size |
|---|---|---|---|
| 3.1 | **Port the remaining Cloudflare WAF categories** into `scripts/seeds/internal_taxonomy.json`. **Unblocked by 1.3:** eight named categories are still unported, and three of them — PathTraversal, SensitivePathAccess, RCE_CommandInjection — already have reviewed regex, CWE mapping and known weaknesses written up in the team's own pattern document, so they can be ported almost verbatim. The other five (KnownCVE_Signature, SSRF, NoSQLi, OpenRedirect, XSS) have names and observed payloads but no documented logic yet. | both | M |
| 3.2 | **Add a CyberArk log source signature.** Deliberately skipped: I could not verify the field names, and a guessed signature that looks authoritative is worse than none. Needs one real sample. | both | S |
| 3.3 | **Grow the internal taxonomy for sources Sigma does not reach.** The FortiGate fixture produced 1 candidate from 3144 Sigma rules; the appliance syslog produced none. That gap is what the taxonomy exists to close, and it only closes one project at a time. | both | L |
| 3.4 | **Widen the backtest's supported Sigma constructs.** Rules using anything the evaluator does not implement are reported as not backtested, with the reason — never miscounted. Worth extending once real samples show which constructs actually come up. | eng | M |
| 3.5 | **Add log source signatures as new formats appear.** Each unrecognised source currently yields a fingerprint with no logsource triple, which means no Sigma rule can be confirmed and everything falls to the hypothesis path. | eng | S each |

## 4. Deferred by the blueprint itself

Not oversights. `docs/BLUEPRINT.md` explicitly places these after the core is proven.

| # | Task | Reference | Size |
|---|---|---|---|
| 4.1 | **Atomic Red Team synthetic telemetry** to validate that a rule actually fires against the technique it targets, rather than only backtesting a static sample. | 5.6, "bukan MVP" | L |
| 4.2 | **Push to Kibana via the Detection Rules API**, manual-trigger only, never automatic. Would still end at the human review checkpoint. | §6, "tahap lanjut" | M |
| 4.3 | **Package as a single executable** (PyInstaller) so teammates need no Python. Only once the logic has stopped changing. | 8.6, "belakangan" | M |
| 4.4 | **Map to frameworks beyond MITRE ATT&CK** — NIST CSF, CIS Controls, D3FEND. The matching structure was kept generic for this. | §3 | M |

## 5. Hygiene

| # | Task | Owner | Size |
|---|---|---|---|
| 5.1 | **Upload retention.** `data/uploads/` keeps every uploaded sample forever. These are client logs; they should expire, or at least be prunable from the UI. | eng | S |
| 5.2 | **Corpus refresh cadence.** The blueprint asks for periodic refreshes of the Sigma and integrations clones. `scripts\setup.ps1` refreshes them, but nothing prompts anyone to run it. A staleness note on the results page would be enough. | eng | S |
| 5.3 | **Clear the verification runs** left in the local job history from UI testing. Cosmetic; they are visible in History. | eng | S |

---

## Not on this list, deliberately

- **Auto-reload for the dev server.** It restarts the process on any file change,
  which kills a job running in the background. That contradicts the batch/async
  principle in `docs/BLUEPRINT.md` §3 and trades a visible failure for an invisible
  one. Item 1.1 addresses the same problem without that cost.
- **Anything that would put an LLM in the matching path.** Non-negotiable.
- **Anything that sends log content off the machine.** Non-negotiable.
