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
| 1.4 | ~~**Confirm the WAF `RuleID` values.**~~ **Done 2026-08-24 — the premise did not hold.** Findings below. | both | done |
| 1.6 | ~~**Decide how to read the Sentinel export's timestamps.**~~ **Done 2026-08-24.** Decided per column from evidence, refused when the column does not settle it. What was decided and why is below. | both | done |

### 1.4 — what the confirmation found

**There is no `RuleID` to confirm.** The team's production Cloudflare data reaches
Sentinel as the **HTTP-requests** dataset, not `firewall_events`, and that shape carries
no rule identifier at all. Its columns are `ClientRequestURI`, `WAFAttackScore`,
`WAFSQLiAttackScore`, `WAFXSSAttackScore`, `WAFRCEAttackScore` and `WAFAction`.

So `100015` stays a placeholder, now labelled as one on the entry, and the branch it
scopes is marked as applying only to a `firewall_events`-shaped log. That is the honest
state: not confirmed, and not confirmable from the data that exists.

What the environment actually discriminates on is the **WAF Attack Score**, which is a
better signal than a rule ID for this purpose — it is the thing that catches a payload
fuzzed just enough to miss a managed-rule signature, which is exactly what a
signature-scoped branch cannot see.

Three things follow, all done:

- **A new entry, `cloudflare-waf-low-attack-score-not-blocked`**, ported from Tier 1 of
  the team's own two-tier attack-score runbook: score ≤ 20 *and* an action that is not
  block or challenge, meaning the payload reached the origin. One event is enough,
  which is the runbook's own judgement. Tier 2 is deliberately absent: it needs ≥5 hits
  across ≥3 *distinct days* in a rolling window, and the entry format can express a
  count inside a window but not a count of active days. It stays a Sentinel analytic.
- **The plan caveat is recorded as an assumption**, because it decides whether the rule
  is buildable at all: numeric scores are Enterprise-only, Business gets the categorical
  `WAFAttackScoreClass` instead, and even on Enterprise the field only reaches Sentinel
  if it was selected when the Logpush job was configured. If the column is missing the
  query errors rather than returning nothing.
- **The `cloudflare_http_requests` signature now recognises the score fields**, so this
  shape classifies at 0.95 confidence instead of scraping by on the generic ones.

A new fixture, `tests/fixtures/cloudflare_http_requests_attackscore.csv`, covers it:
the entry fires on the four low-score requests that were not blocked and stays quiet on
the three that Cloudflare had already stopped.
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

| 1.7 | ~~**Show the evidence on every result card.**~~ **Done 2026-08-24.** Both outcomes now carry the event time, real sample events, and — on the rejection path — a field-by-field account of what is missing. Below. | eng | done |

| 1.8 | ~~**Visual pass, and four table bugs.**~~ **Done 2026-08-25.** The stylesheet was rebuilt around a deeper palette, real elevation and a working sticky header. Four table bugs found and fixed — details below. | eng | done |

### 1.8 — four table bugs, all from one line of CSS

`.table-wrap { overflow: hidden }` was there to clip the rounded corners. It cost
four things, and none of them announced themselves:

1. **The sticky header never stuck.** `overflow: hidden` makes an element the
   nearest scroll container for `position: sticky` inside it. `.table-wrap` never
   scrolls vertically, so a header written as `top: var(--header-h)` — deliberately
   the height of the site bar — had no scroll range to stick within. Scrolling a
   19-field table simply lost the column names.
2. **The horizontal scrollbar ate the last row.** `.table-scroll { overflow-x: auto }`
   landed on top of it, computing to `overflow-y: hidden`. On Windows the
   scrollbar is laid inside the box and the box cannot grow, so the bottom row
   was clipped behind it.
3. **`max-width` on a `<td>` does nothing.** In auto table layout browsers treat it
   as advisory and size to content, so one 160-character `message` stretched the
   events table far off-screen. The cap now lives on a block inside the cell,
   which does honour it.
4. **`width: max-content` fought the wrapping.** It measures the unbroken width, so
   `word-break` inside never got a chance. Removed.

Corners are rounded on the edge cells instead, and sticky is now opt-in
(`.table-wrap > table`) — a four-row table inside a card has nothing to stick for,
and a header that detaches from one mid-scroll reads as a fault.

The visual pass: a deeper, more saturated palette with a proper dark mode;
three elevation levels instead of one flat shadow; a translucent blurred header;
numbered step pills; stat tiles with a state-coloured hairline so the tile reads
before its number does; circular rank badges; a rotating chevron on every
disclosure; zebra striping and row highlight on the standalone tables only;
`:focus-visible` rings throughout; and `prefers-reduced-motion` honoured globally
rather than per-animation.

Two constraints held the whole way: no web fonts and no CDN, so every face is a
system font; and anything using `color-mix()` either has an `@supports` fallback
or degrades to something that still carries the meaning — a state colour is never
allowed to disappear because a browser is a version behind.

### 1.7 — a verdict a reviewer can check

Every card stated a conclusion and nothing a reviewer could weigh it against.
*"5 of 37 sample events match"* is a number; a reviewer who cannot see the five
events is being asked to trust the count. The rejection cards were worse: they
said **rejected** and listed which validation step failed, but the thing that
actually goes back to the client — *which field is missing* — was buried in
prose inside a check's detail cell.

Three things now appear on every result, on the page and in the downloaded
markdown alike:

- **Event time**, named. Which column it comes from, its granularity, and
  whether it is split across two columns or unreadable as written. Every rule is
  time-scoped on that column, so a reviewer should not have to go back to the
  structure page to find out which one it is.
- **The events themselves.** On the match path, the events the logic fired on,
  led by the columns it keyed on. On the rejection path, events from the sample,
  so the list of missing fields is read against what the data does carry. The
  raw timestamp is shown as the sample wrote it, with the engine's reading of it
  beside it *only when the two differ* — which is exactly the day-first case 1.6
  introduced. Blank columns are dropped, because a row of thirty dashes hides
  the four values that matter, and one event is shown in full underneath so the
  narrowed columns do not hide context.
- **Why it was rejected, in the client's terms.** A field-by-field table of what
  the hypothesis asked for and what the sample answered with, and a headline
  sentence naming the gap. A rejection that is *not* about a missing field says
  so instead — "every field this hypothesis needs is present; what the sample
  does not give is a longer sample" is a different ask, and dressing it up as a
  field gap would send someone to the client for the wrong thing.

`EventExample` and `build_examples()` sit in the profiler next to `top_values`,
which is the same job: sample the data so a human can review it. The rejection
report holds one set of events shared by every card, since the events are a
property of the sample and not of one hypothesis, while the evidence resolutions
are per hypothesis. Values are truncated at 160 characters rather than omitted —
a payload in a URL is the evidence — and wide tables scroll inside their own box
so the page never scrolls sideways.

Nothing leaves the machine: this renders sample content that was already in
memory, into a page served on `127.0.0.1` and a file written locally.

### 1.6 — the decision: read it from the column, refuse when the column is silent

`16/07/2026 20:26:12.030` under `TimeGenerated [Local Time]` was two separate
problems wearing one coat.

**The format was not recognised at all.** `_ISO_TIME_RE` requires `YYYY-MM-DD`, so a
slash date fell through to dtype `string`, `find_timestamp_source` never considered
it, and the engine reported *no timestamp field was found* for a log whose first
column is a timestamp. That is the same failure the split `date`/`time` work existed
to stop: the ask that reaches the client is **add an event timestamp**, for data they
already send. A separator-separated date is now a `date`, or a `timestamp` when it
carries a clock.

**The order genuinely is ambiguous — sometimes.** The rule adopted:

> Decide day-first vs month-first **across the whole column, never from one value**,
> and refuse when the column does not settle it.

One value above 12 in the first position proves day-first; one in the second proves
month-first; both appearing means no single order reads the column, and neither
appearing means the column proves nothing. The decision is made in `profile_fields`,
which sees every value, and carried on `FieldProfile.date_order` — not in
`find_timestamp_source`, which only sees five sampled values and would call a
settled column ambiguous. `parse_timestamp` will not read a slash date without being
told the order, so no caller can accidentally get a guess.

Refusing had to stay distinct from *absent*, or it would have recreated the bug at
the other end. `TimestampSource.is_readable` is that distinction: the source is still
returned, spans and projections degrade to *not projectable*, and the ask becomes
**confirm whether the date is day-first or month-first** rather than *add a
timestamp*. `_contextual_filtering` needed its own branch for the same reason — it
would otherwise have reported "no sub-minute component" about a value ending
`.030`, which is false. Nothing parsed; that is not the same as coarse.

**`[Local Time]` was the second finding, and it is not cosmetic.** The column says
local and carries no offset. Span and windowing are offset-invariant, so nothing
computed is wrong, but ingest writing it straight to `@timestamp` puts every event
seven hours off for a WIB site. No offset is invented — it is raised as an ingest
requirement, on the runbook and in the rejection report's onboarding list.

On the new fixture the readable path now projects from *sample time span* where it
previously could not project at all; the same file with every day below 13 stays
*not projectable* and says why. Both carry the offset ask. 290 tests pass.

Left undone deliberately: a 12-hour clock with `AM`/`PM` is not read. It is refused
rather than misread, and refusal is already reported, so it surfaces as an ask if it
ever appears.

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
| 3.1 | **Port the remaining Cloudflare WAF categories.** **Three done 2026-08-24** — PathTraversal, SensitivePathAccess, RCE_CommandInjection, from the team's own reviewed pattern document; details below. **Five still to write:** KnownCVE_Signature, SSRF, NoSQLi, OpenRedirect, XSS have category names and observed payloads but no documented detection logic yet, so each needs an analyst to author it. Six further categories from the blueprint's count of fifteen are still unnamed. | both | M |

### 3.1 — the three ported so far

The taxonomy now holds five entries. Against the Cloudflare fixture each finds exactly
the attacks that are in it and nothing else: path traversal on line 13, the three
scanner requests on lines 34-36, SQLi on lines 6-10, and RCE nothing, because that
sample contains no RCE payload.

Two adaptations were needed and are recorded as assumptions on the entries:

- **`(?i)` had to move to the front of the path-traversal pattern.** RE2 accepts an
  inline flag mid-expression; Python rejects one that is not at the start, so the
  pattern would not have compiled at all. Moving it also makes the whole expression
  case-insensitive, which is what the source document lists as its own first
  improvement — `%2E%2E%2F` was not covered before and is now.
- **`http.request.uri` is one field in Cloudflare and two in Logpush.** The patterns
  are applied to `ClientRequestPath` and `ClientRequestQuery` and OR'd, since matching
  the path alone would miss payloads in the query string.

The known gaps their author recorded were **not** silently fixed: encoded backslash and
the other overlong UTF-8 forms for traversal; `.htaccess`, backup artefacts and
framework debug endpoints for sensitive paths; `eval(`, `assert(`, `base64_decode(` and
reverse-shell indicators for RCE. They are written into each entry's `notes` so the
next analyst decides, rather than finding an undocumented divergence from the source.

Two corrections its author had already made **are** carried over: `passwthru` spelled
`passthru`, which without the fix could never match the real PHP function, and the
greedy `${.*}` bounded so it cannot swallow an unrelated span of a large body.
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
