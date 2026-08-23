# Phase 0 smoke test: Cloudflare WAF sample to Sigma rule

Evidence for the Phase 0 Definition of Done in `docs/IMPLEMENTATION_PLAN.md`:
*one log sample can be profiled and matched (by hand) to at least one Sigma rule.*

Everything below was traced manually. No engine matching code exists yet, and none
was written for this — that is Phase 1.

Run date: 2026-08-23. Sigma corpus at `da9bb07`, 3144 rules.

---

## 1. The sample

`tests/fixtures/cloudflare_waf_firewall_events.csv` — 37 events, 19 columns, shaped
like a Cloudflare Logpush `firewall_events` export. Synthetic, built for this test:
all addresses come from the RFC 5737 documentation ranges, no client data.

Time range 09:00:03Z to 09:10:04Z (~10 minutes). Contents by eye: normal browsing,
5 SQL injection attempts, 2 XSS attempts, 1 path traversal, a 16-request failed-login
burst from one IP, and a 3-request scanner sweep.

## 2. Field profile, by hand

The columns that carry detection value:

| Field | Example | Entity type | Note |
|---|---|---|---|
| `Datetime` | `2026-03-11T09:02:05Z` | timestamp | RFC 3339, second granularity |
| `ClientIP` | `198.51.100.203` | ip | 7 distinct values |
| `ClientRequestHost` | `shop.example.co.id` | domain | 2 distinct |
| `ClientRequestMethod` | `GET` | — | GET / POST only |
| `ClientRequestPath` | `/products` | url path | |
| `ClientRequestQuery` | `?category=1' UNION SELECT...` | url query | **URL-encoded**, see §7 |
| `ClientRequestUserAgent` | `sqlmap/1.7.2#stable` | user agent | |
| `Action` | `block` | — | allow / block / managed_challenge / log |
| `Source` | `waf` | — | waf / firewallRules / rateLimit / unknown |
| `RuleID` | `100015` | — | empty when `Source` is `unknown` |
| `EdgeResponseStatus` | `403` | — | edge verdict |
| `OriginResponseStatus` | `401` | — | empty when blocked at the edge |

Null rate is the notable one: `RuleID`, `ClientRequestQuery`, and `OriginResponseStatus`
are all empty on a large share of rows, and each emptiness is meaningful rather than
missing data. A profiler that reports them as "high null rate, low value" would be
drawing the wrong conclusion — worth remembering when `field_profiler.py` is written.

**Fingerprint:** `category: webserver`, `product: cloudflare`, `service: firewall_events`,
data category `application_logs`.

## 3. ECS gap analysis

Per `docs/BLUEPRINT.md` 5.2, official integration first. There are two Cloudflare
packages in the local corpus, and the obvious one is the wrong one:

- `cloudflare` — data streams `audit`, `logpull`. `logpull` is the HTTP-requests
  dataset and uses `ClientRequestURI` (path and query combined). Not our shape.
- `cloudflare_logpush` — 22 data streams including **`firewall_event`**, which maps
  `ClientRequestPath` and `ClientRequestQuery` separately. This is the match.

So: **official integration available, no custom mapping needed.** Verified against
`data/elastic-integrations/packages/cloudflare_logpush/data_stream/firewall_event/elasticsearch/ingest_pipeline/default.yml`:

| Sample field | ECS field after the official pipeline |
|---|---|
| `Datetime` | `@timestamp` (accepts UNIX_MS, ISO8601, `yyyy-MM-dd'T'HH:mm:ssZ`) |
| `ClientIP` | `source.ip` |
| `ClientASN` | `source.as.number` |
| `ClientCountry` | `source.geo.country_iso_code` |
| `ClientRequestHost` | `url.domain` |
| `ClientRequestPath` | `url.path` |
| `ClientRequestQuery` | `url.query` |
| `ClientRequestScheme` | `url.scheme` |
| `ClientRequestMethod` | `http.request.method` |
| `EdgeResponseStatus` | `http.response.status_code` |
| `Action` | `event.action` |
| everything else | `cloudflare_logpush.firewall_event.*` (vendor namespace) |

What the integration does **not** close:

1. `http.response.status_code` is copied from the **edge** status. `OriginResponseStatus`
   keeps its vendor-namespaced field. For this sample the two agree, but a rule that
   means "the origin rejected it" must read the vendor field, not the ECS one.
2. Four more fields stay vendor-namespaced with no ECS target: `Source`, `Kind`,
   `EdgeColoCode`, `ClientRequestProtocol`.

> **Correction (Phase 1).** This section first claimed a third gap: that the data
> stream has no `user_agent` processor, leaving ECS `user_agent.original` empty.
> That was wrong. The pipeline does run one (`default.yml` line 324); the original
> grep that produced the claim was truncated by `head -25` and never reached it.
> `ClientRequestUserAgent` is mapped. The automated ECS gap analysis built in
> Phase 1 disagreed with the hand-written table here, which is how the error
> surfaced.

## 4. The Sigma match

**Rule:** `SQL Injection Strings In URI` — `5513deaf-f49a-46c2-a6c8-3f111b5cb453`
(`rules/web/webserver_generic/web_sql_injection_in_access_logs.yml`)
`logsource.category: webserver` · `attack.initial-access`, `attack.t1190` · level `high`

The logsource is category-only, with no product or service constraint, so the
fingerprint's `webserver` category is enough to make this rule a candidate.

Field requirements against the sample:

| Sigma field (webserver schema) | Sample field | Present? |
|---|---|---|
| `cs-method` | `ClientRequestMethod` | yes |
| `sc-status` | `EdgeResponseStatus` | yes |
| unnamed `keywords` block | full-text over the event | yes |

**Verdict: feasible.** Every field the rule depends on exists in the sample.

## 5. Manual backtest

Rule condition: `selection and keywords and not filter_main_status`, i.e.
`cs-method` is GET, one of the 30 literal keywords appears anywhere in the event, and
`sc-status` is not 404. Sigma string matching is case-insensitive by default.

**2 of 37 events match (5.4%):**

| Line | Time | Client | Keyword hit |
|---|---|---|---|
| 6 | 09:02:05Z | 198.51.100.203 | `UNION SELECT` |
| 9 | 09:02:19Z | 198.51.100.203 | `information_schema.tables` |

The sample contains **5** SQL injection attempts. This rule catches 2 and misses 3:

- line 7 `?id=8812+OR+1%3D1--` — the keyword list has `or 1=1#`, with a trailing hash.
- line 8 `?q=x'+AND+SLEEP(5)--` — the list has `select%28sleep%2810%29`, not bare `sleep(`.
- line 10 `?ref=1';WAITFOR+DELAY+'0:0:5'--` — a POST, excluded by `cs-method: 'GET'`.

This is not a defect in the Sigma rule; it is the heuristic ceiling `docs/BLUEPRINT.md`
§2 and §10 warn about, showing up on the very first sample. It is also the concrete
argument for the internal taxonomy, which is the point of the next section.

## 6. Internal taxonomy cross-check

The same sample against the seeded entry `cloudflare-waf-sqli`
(`scripts/seeds/internal_taxonomy.json`):

**5 of 5 SQL injection attempts caught, 0 false positives.** It sees what the Sigma
rule misses because it reads Cloudflare's own WAF verdict (`Source`/`Action`/`RuleID`)
instead of guessing from payload text alone.

Two things this cross-check turned up, both now fixed in the seed:

- **The WAF-verdict branch was too broad.** As first written it matched any WAF block,
  which on this sample meant 3 false positives — two XSS blocks and a path traversal
  block — under an entry named "SQL injection". Scoping the branch to the SQLi managed
  rule (`RuleID`) removed all three. The rule IDs are ruleset-specific, so they are
  recorded as an onboarding item to confirm against the client's WAF config, not as a
  universal constant.
- **URL-decoding is load-bearing.** The payload regex matches 3 of 5 attempts against
  the raw query string, and 5 of 5 against the URL-decoded one: `+` stands in for a
  space, so `\s` stops matching. Rather than complicate every regex, ingestion should
  URL-decode. Recorded as an assumption on the entry and as a Phase 1 requirement.

The second entry, `cloudflare-waf-credential-stuffing`, **does not fire on this sample**:
the burst is 16 failed logins in 51 seconds, and the seeded threshold is 20 in 5 minutes.
Reported rather than tuned away — a 37-event fixture is too small to justify a threshold
either way, and picking the number that makes a synthetic sample light up is exactly the
mistake the Phase 4 backtest exists to prevent.

## 7. pySigma toolchain check

`sigma convert -t lucene --without-pipeline` on the matched rule produces:

```
cs-method:GET AND (*@@version* OR ... OR *UNION\ SELECT* ...) AND (NOT sc-status:404)
```

Toolchain works — pySigma 1.5.0 with pySigma-backend-elasticsearch 2.1.1 (targets:
`lucene`, `eql`, `esql`, `elastalert`).

Note the `--without-pipeline`: the backend refuses to convert without a processing
pipeline, and the shipped ones (`ecs_windows`, `ecs_zeek_beats`, `ecs_kubernetes`,
`ecs_macos_esf`) have no webserver mapping. Un-piped output keeps the raw Sigma field
names `cs-method` and `sc-status`, which exist in no Elastic index anywhere. Phase 1
needs its own processing pipeline mapping the webserver schema onto ECS.

## 8. Verdict

**Phase 0 Definition of Done: met.** One sample profiled and matched by hand to a Sigma
rule, with the ECS mapping traced to an official integration and the toolchain converting
that rule to a real Elastic query.

What this does not establish: that matching generalises. One sample, one log source, one
rule, on a fixture built for the purpose. Phase 1's DoD — 3 to 5 real project samples —
is the test that matters.

## 9. Carried into Phase 1

1. **URL-decode query strings at ingestion.** Measured cost of skipping it: 2 of 5
   detections on this sample.
2. **Write a webserver processing pipeline for pySigma.** Without one, converted rules
   reference `cs-method` / `sc-status`, which match nothing.
3. **Empty is not missing.** `RuleID`, `ClientRequestQuery`, and `OriginResponseStatus`
   are meaningfully empty; `field_profiler.py` should not treat a high null rate as low
   value on its own.
4. **Resolve integrations by data stream, not by vendor name.** `cloudflare` and
   `cloudflare_logpush` are both "Cloudflare"; only one has a `firewall_event` data
   stream matching this shape. `ecs_gap.py` has to match on data stream fields, and a
   vendor-name lookup would have picked the wrong package here.
5. **Record what an official integration leaves unmapped.** Here: `http.response.status_code`
   carries the edge status rather than the origin status, and `Source`, `Kind`,
   `EdgeColoCode`, and `ClientRequestProtocol` get no ECS target at all.

## Reproduce

```powershell
scripts\setup.ps1                                   # idempotent; refreshes corpora
.venv\Scripts\python.exe -m engine.storage.db --status
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\sigma.exe convert -t lucene --without-pipeline `
    data\sigma-corpus\rules\web\webserver_generic\web_sql_injection_in_access_logs.yml
```

The hand trace itself is re-derivable from three committed files: the fixture, the
Sigma rule above, and `scripts/seeds/internal_taxonomy.json`.
