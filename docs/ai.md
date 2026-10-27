# AI analysis, models and cache

[Back to deployment choices](../README.md)

## AI vulnerability discovery and blocking rules

Filtr uses AI with provider-hosted web search as its automatic vulnerability discovery engine. Unexpired per-component reviews are reused; missing/expired entries are researched within the configured deadlines. The default lifetime is one day.

Accepted findings appear under `policy.ai.discoveries` with their exact `component_index`, CVE, native-search source URL, affected-version explanation, suggested `fixed_version`, `coverage_note`, optional `restriction`, and optional `emergency` recommendation. A validated restriction creates an `ai_discovery` rule for that exact installed package/version. No narrow restriction means **advisory only**: the finding is included under `uncovered_vulnerabilities` in remediation/webhook reports and does not stop unrelated traffic. Unsupported or overly broad proposed filters are discarded while the evidenced vulnerability stays visible.

A request restriction ANDs its method, path-prefix and header conditions, then requires any configured body marker. Empty methods/path/headers/body patterns omit that selector. Header matching supports case-insensitive `exact`, comma-separated `token`, `present` (with an empty value), and `media_type` for Content-Type without parameters such as a multipart boundary. Methods alone, root path alone, presence of ubiquitous headers, and forwarding headers used as transport claims are rejected as narrow mitigations. Body matching uses bounded ASCII literals and the existing decoded views; no model-supplied regex or executable code runs. Each filter has at most 8 methods/headers, 64 body markers and a 512-byte path prefix; at most 128 scoped request filters are compiled. Specific filters can still block legitimate requests in the selected class.

For example, a **source-justified** Brotli request restriction can use the following `restriction`; it matches `Content-Encoding: br` and encoding lists containing `br`, without matching a substring such as `zebra`:

```json
{
  "methods": [],
  "path_prefix": "",
  "headers": [{"name": "content-encoding", "kind": "token", "value": "br"}],
  "body_patterns": []
}
```

This is an API shape example, not a built-in Bun/CVE fix. In v0.1.2, Filtr checks this rule before decoding the incoming body; a match returns 403. Without the restriction, supported compressed bodies undergo bounded decompression and the same body inspection as ordinary requests. Once a truthful patched SBOM removes the applicable restriction, valid Brotli requests can reach the upstream again. See [HTTP behavior](operations.md#http-behavior).

This mitigates the incoming request path identified by the rule. `Content-Encoding: br` describes an incoming Brotli body; `Accept-Encoding: br` asks for a compressed response and is not the same condition. Outgoing application connections and response-body processing are outside this ingress filter's scope. That boundary does not invalidate a targeted incoming-body mitigation. If application code decodes Brotli carried inside another format, such as a JSON field, a Content-Encoding rule alone does not identify that path; any additional restriction needs evidence about how that application accepts input.

Filtr's listener accepts HTTP/1.0 and HTTP/1.1 over TCP, and its upstream client uses HTTP/1.1. [HTTP/3 runs over QUIC](https://www.rfc-editor.org/rfc/rfc9114.html); Filtr does not accept or inspect QUIC/HTTP/3 or HTTP/2 frames. If an ingress terminates those protocols, only its resulting HTTP/1 request reaches Filtr. A protocol-parser vulnerability at that ingress must be addressed there, for example by disabling its affected protocol. AI must report this limitation and infrastructure action rather than fabricate an HTTP/3 header filter or block unrelated HTTP/1 traffic. Client-supplied forwarding headers do not prove the original transport.

`policy.active_rules` contains enforced targeted curated rules; broad catalogue actions are listed under `policy.advisory_rules`, with matching per-component `advisory_rules` IDs. AI enhancements may add evidenced literal markers to enabled targeted curated bases. They cannot add `deny_all`, `deny_write`, allow rules or execute maintenance. Full blocking is a separate operator/critical-risk decision, described in the [traffic-control guide](api.md#traffic-modes-and-emergency-blocking).

`policy.inventory_gaps` retains index/reason records, while `inventory.gaps` on upload/status/refresh adds readable names, types, images and guidance. Gaps are nonblocking diagnostics. A known OS without a PURL is an identifier-format gap; inspect OS-package coverage separately. Never invent versions, identities or reachability assumptions to clear a report.

**A completed AI review is not a complete CVE scan.** Bounded searches and model assessments can miss advisories or misread exposure. Rejected proposals remain visible; missing/failed AI keeps targeted static filtering active. A previously established opt-in emergency decision is retained until a complete review updates it or an operator selects `filter`. The admin API remains available during full blocking.


## AI providers, leaderboard selection and backup

Set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or both in the process environment before starting Filtr. OpenAI uses the [Responses API with strict structured output](https://developers.openai.com/api/docs/guides/structured-outputs) and hosted web search. Anthropic uses the Messages API with hosted web search and a strict `submit_review` reporting tool. The reporting tool returns structured data; it does not execute application code or external actions. No additional SDK or runtime dependency is required. Without either key, `policy.ai.status` is `not_configured` and only curated static mappings remain active.

Without a model override, only a valid **SBOM upload/update** with AI configured fetches the [DeepSecBench results](https://vercel.com/ai-gateway/leaderboards/deepsecbench/results.json). Filtr selects the smallest positive rank among providers with credentials and atomically saves a snapshot beside the SBOM (`data/sbom.json.leaderboard.json` by default). Restarts use this saved snapshot and make no leaderboard request. The snapshot includes the normalized inventory/static rule mapping, must match the current inventory/catalogue, and is limited to 64 MiB. Missing, corrupt or mismatched snapshots trigger the configured Luna backup or static-only fallback; startup never repairs them by fetching rankings. Re-upload an SBOM to refresh the snapshot. Timed and manual review refreshes reuse it; they do not fetch rankings.

Set `--ai-provider openai|anthropic` / `FILTR_AI_PROVIDER` to restrict primary selection to that provider. The winner's reasoning/effort setting is also used. Array order and model version numbers do not determine the winner. Primary selection follows the applicable uploaded leaderboard snapshot; there is no fixed primary model. Gateway Claude version dots are converted to hyphens for the direct Anthropic API.

If the primary request fails, times out, refuses, or returns invalid/incomplete output, Filtr makes one backup attempt with **OpenAI `gpt-5.6-luna` at `xhigh`**, provided `OPENAI_API_KEY` is configured. It also uses this backup if the leaderboard cannot be fetched/validated or has no eligible model. An Anthropic key cannot authenticate the OpenAI backup. The backup still applies when `FILTR_AI_PROVIDER=anthropic`; that setting restricts the primary only. If Luna was already the selected primary, it is not requested twice. There are no further model fallbacks; transient HTTP failures have bounded retries within the review deadline. If no backup is available or it also fails, Filtr keeps only static mappings active.

Filtr sends the normalized inventory and enabled curated rules to the selected provider, and to OpenAI if backup is needed. This includes component names and package/version identifiers, which can reveal private dependency choices. Hosted web-search queries may also disclose those identifiers to the provider's search infrastructure. Filtr does not include the original SBOM document, admin token, proxied requests or request bodies. Credentials go only to their provider's request header; the leaderboard receives no credentials or inventory. OpenAI requests set `store: false`; this is an API request setting, not a claim about all provider data retention.

The AI receives uncached/expired components in bounded batches and searches the [research sources](#research-sources), prioritizing runtimes and recent critical vulnerabilities. Each discovery must identify a component supplied in that batch, a CVE, an HTTPS source returned by the provider's native web-search results, an affected-version explanation and a fixed version when known. Accepted discoveries appear in `policy.ai.discoveries`; only validated narrow restrictions generate `ai_discovery` rules for the exact installed package/version. Other findings stay advisory-only. An arbitrary URL written by the model is insufficient.

A native-search source establishes that the provider retrieved a URL. It does not independently verify the model's interpretation of affected versions or exploitability. Only validated narrow restrictions are enforced by default. Findings without one are advisory-only; whole-upstream blocking is controlled separately through traffic mode and optional critical-risk escalation. Review cited advisories before patching and regenerate the SBOM from the deployed artifacts.

AI enhancements can add evidenced literal token restrictions to an enabled curated basis. Broad read-only and deny-all enhancements are rejected. Every enhancement must name an existing component index and a curated rule enabled for that exact component/version. The server supplies these enhancements' source URLs and version scope. It rejects invented bases, other components' rules, empty or oversized patterns, unsupported actions and extra fields. Package names, advisory text and search results are treated as untrusted data. Model text is never executed as code, regex or shell commands; only provider-hosted web search and structured reporting are available.

Proposals only add validated targeted restrictions. The model cannot remove targeted rules, add allow exceptions, broaden installed version ranges, change traffic mode, or change proxy configuration. Optional emergency recommendations are evaluated separately against the operator-controlled escalation setting. Static mappings serve traffic during review. After a valid, completed response from either primary or backup, accepted discoveries and AI enhancements activate together. If neither succeeds, only targeted static filters remain active; persisted operator mode and the last complete emergency decision are retained. Structurally valid AI rules can still be inaccurate or block legitimate traffic; validation does not prove exploit coverage.

`policy.ai` reports `pending`, `complete`, `partial`, `failed` or `not_configured`, with the final provider/model, reasoning level, leaderboard rank, response ID, concise review, component count, discoveries, applied rule IDs and per-proposal rejection reasons. `leaderboard_source` is `sbom_update`, `saved_snapshot`, `model_override` or `review_cache`. `attempts` records each model and its error (null on success); `fallback_used` identifies an attempted backup, and `selection_error` explains failed leaderboard selection/cache access even when backup succeeds. The fixed backup has no leaderboard rank. `partial` means proposals were rejected or a cache-only preview has unreviewed components. Accepted targeted restrictions can still apply; an incomplete review never clears an existing automatic emergency decision. `policy.generated_rules` distinguishes targeted `ai` enhancements and `ai_discovery` restrictions; it is empty during static-only fallback. The upload response and `GET /v1/rules` expose this metadata without credentials.

Anthropic requests enable [ephemeral prompt caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching) at the top level and on the reusable system prefix. `policy.ai.usage` reports input/output tokens, cache creation/read tokens and web-search requests from completed responses, including paused-turn continuations. Cache eligibility and hits depend on the provider's token thresholds, prefix reuse and cache lifetime; enabling caching does not guarantee every request hits. OpenAI's reported cached-input tokens are exposed in the same usage fields.

AI reviews send only uncached/expired component versions in batches of at most 128 KiB, with four batches in flight and at most 512 batches. Identical package/version/rule keys share a review, including duplicates in one upload. Cached components are not sent again. Each component carries its original global index; proposals are restricted to component/basis pairs actually supplied in that batch. Selection refreshes the leaderboard once per valid upload, and all batches use that selected primary with Luna fallback when configured. A new AI policy is compiled after every batch finishes successfully. Individual invalid proposals are rejected; accepted restrictions may apply with status `partial`. Any failed or timed-out batch leaves only static mappings active. `policy.ai.batches_total`, `batches_completed`, `input_bytes` and each attempt's `batch_index` report the work completed.

The prompt requests at most eight enhancements and eight discoveries per batch. Each provider attempt has a 300-second default deadline, a 1 MiB response limit, 16,384 output tokens and at most 32 enhancements plus 32 discoveries. Each provider request permits at most five hosted searches; Anthropic paused turns can continue through at most four responses within the same attempt deadline. A search-tool failure fails that batch. The complete review has a separate 900-second deadline, including selection, retries, continuations and backup attempts. HTTP 429 and server errors can be retried twice with bounded backoff within these deadlines. Enhancements and discoveries have bounded counts; excess or invalid proposals are reported as rejections. Summary text is capped at 4,096 characters. A completed review is not an exhaustive vulnerability audit, and missing evidence or credentials never becomes proof of safety.

Use `--ai-timeout-secs` / `FILTR_AI_TIMEOUT_SECS` for each provider attempt and `--ai-review-timeout-secs` / `FILTR_AI_REVIEW_TIMEOUT_SECS` for the complete review (each 1–3,600 seconds). A single HTTP request is capped at 300 seconds. On SBOM updates, the leaderboard has a separate timeout of the smaller of five seconds and the provider deadline, a 256 KiB response limit and a 1,000-entry limit. Saved snapshots support inventories up to the 64 MiB document limit and remain bound to that exact inventory/static catalogue. `--ai-leaderboard-url` / `FILTR_AI_LEADERBOARD_URL` overrides the results URL. `--ai-url` / `FILTR_AI_URL` defaults to `https://api.openai.com/` and implements `/v1/responses`; `--anthropic-url` / `FILTR_ANTHROPIC_URL` defaults to `https://api.anthropic.com/` and implements `/v1/messages`. Provider endpoints must be origins without paths; all URLs reject credentials, queries and fragments and require HTTPS, with HTTP allowed only on loopback for testing. Redirects are not followed. Upload/startup processing can wait up to 900 seconds with the default complete AI review deadline. Calls can incur provider charges when keys are configured.

## Research sources

Filtr v0.1.2 adds [cve.now](https://cve.now/) to the research instructions shared by OpenAI and Anthropic, including backup attempts. Its [source reference](https://cve.now/llms.txt) describes aggregated CVE/advisory feeds, exploitation signals and labeled model-written summaries. Filtr uses it through provider-hosted web search, with no new service credentials or direct database client.

The AI is instructed to use one of its existing targeted searches for `site:cve.now` and the supplied package identities/versions. It then checks the original vendor/project advisories for affected ranges, fixed versions, exploit conditions and narrow HTTP mitigations, citing primary evidence retrieved by native search. Aggregated summaries, severity scores and exploitation labels are leads, not sufficient evidence for a blocking rule. Source selection and interpretation remain model assessments; Filtr validates the returned source provenance and rule structure, not the truth of an advisory.

If cve.now is unavailable, unindexed or has no relevant match, the instructions continue primary-advisory research within the same search/time budgets. An empty feed or missing affected-version data does not establish safety. Adding this source neither increases search limits nor adds another model review per component. Search-tool/provider failures retain the existing static-only fallback.

Filtr does not upload an SBOM or lockfile to cve.now's stack service, install its MCP server or invoke `check_stack`. The prompt explicitly forbids these actions; only the existing hosted search and structured reporting tools are available. Search queries and page visits can disclose package identifiers through the provider's research infrastructure, as described above.

Existing valid reviews are preserved by a narrowly scoped migration from the previous targeted-review cache format. Their findings, restrictions and original timestamps remain unchanged, and cache-only requests leave the cache file untouched. New source guidance takes effect for missing/expired components during the next permitted review. Do not clear a working cache just to upgrade. An explicit `POST /v1/refresh` can apply the guidance immediately to the installed inventory when cache-only mode is disabled, but discards all reviews and can incur full-inventory charges.

## Control AI cost and cache freshness

| Environment variable | CLI flag | Default and behavior |
| --- | --- | --- |
| `FILTR_AI_PROVIDER` | `--ai-provider` | Unset: choose the highest-ranked model among providers with credentials. Set `openai` or `anthropic` to restrict primary selection. |
| `FILTR_AI_MODEL` | `--ai-model` | Unset: use leaderboard selection. Set an exact native model ID to pin the primary and skip leaderboard requests. |
| `FILTR_AI_REASONING` | `--ai-reasoning` | Unset: use leaderboard effort for automatic selection, or provider defaults for a pinned model. Set a supported effort explicitly to override it. |
| `FILTR_AI_CACHE_TTL_SECS` | `--ai-cache-ttl-secs` | `86400` (one day): reuse completed component reviews and automatically refresh expired entries. `0` disables cache reuse and the expiry timer. |
| `FILTR_AI_CACHE_ONLY` | `--ai-cache-only` | `false`. Set `true` to forbid provider/search/leaderboard calls and automatic research; use matching unexpired cached reviews only. |
| `FILTR_AI_HTTP_RETRIES` | `--ai-http-retries` | `2`. Additional retries for HTTP 429/5xx per provider request; accepts 0–2. Set `0` to send each request once. Provider web-search continuations are still part of the same review, and a configured backup can still run. |

Cache-only mode also applies on startup and to manual refresh requests. It does not clear or write the cache, fetch rankings, extend timestamps or turn missing reviews into a clean assessment. `GET /v1/status` exposes `ai_mode.cache_only`; preview results report the effective mode. Uploads require complete cached coverage and otherwise return 409 without changing the installed policy. See [cache-only installation](api.md#install-using-cached-reviews-only). The normal one-day refresh behavior resumes when this mode is disabled and Filtr restarts. This option is intended for controlled offline use and repeatable demonstrations; expired knowledge remains expired.

Pin a model in `.env` to skip leaderboard selection:

```dotenv
FILTR_AI_PROVIDER=anthropic
FILTR_AI_MODEL=REPLACE_WITH_YOUR_NATIVE_MODEL_ID
FILTR_AI_CACHE_TTL_SECS=86400
# Optional, only for models that support the chosen effort:
# FILTR_AI_REASONING=low
```

Replace the model placeholder with your provider's exact model ID. `openai/<model-id>` and `anthropic/<model-id>` prefixes also select the provider explicitly; a conflicting `FILTR_AI_PROVIDER` is rejected. A bare ID uses the configured provider, or the only provider with credentials. Pinned models use their provider's default reasoning settings unless `FILTR_AI_REASONING` is set. `default`/`none` omit explicit reasoning parameters; other accepted values are `low`, `medium`, `high`, `xhigh` and `max`, subject to model support. The model must support the provider's hosted web search and structured reporting/JSON interface. A failed primary attempts the existing `gpt-5.6-luna` backup when `OPENAI_API_KEY` is present; if no attempt succeeds, static-only filtering remains. The override and effort apply to the primary; the backup retains its configured `xhigh` effort. Backup and retries can consume additional calls.

Filtr persists per-component reviews beside the SBOM as `sbom.json.ai-cache.json` (under `/data` in Docker). Completed reviews with accepted findings **and completed reviews with no findings** are reusable. Cache keys include normalized package identity, exact version and enabled curated rules. Model/provider/effort settings, provider endpoint, prompt or schema changes invalidate reuse unless an explicit compatible migration is provided, such as the additive cve.now source change above. A finding is rebound to the current component index and validated again before activation, so reordering an SBOM does not associate it with another package. Duplicate identities share a review. Cache entries describe individual components; they do not establish safety for interactions between newly combined systems.

`FILTR_AI_CACHE_TTL_SECS` / `--ai-cache-ttl-secs` defaults to **86400 seconds (one day)**. A running instance automatically researches entries as they expire, even without uploads. Only missing/expired items are sent; valid entries retain their original check time. Restarts also use unexpired entries. Set the value to `0` to disable caching and its automatic expiry timer. Each refresh can incur provider charges. Keep `/data` persistent to avoid unnecessary reviews after container replacement.

For example, uploading the same inventory again within its lifetime reuses completed reviews. Changing one dependency version sends that new version for research while reusing unchanged, unexpired components. Cache hits do not extend expiry. Without a model override, valid SBOM uploads still refresh the leaderboard; automatic expiry and manual refresh use the saved selection without fetching it again.

Only fully validated, completed reviews are written to the cache. Failed, timed-out or partially rejected reviews are not cached as successful empty results. If an automatic review fails, static-only filtering remains and automatic retries stop until an upload, restart or manual refresh, avoiding a tight paid retry loop. Partial valid reviews can apply accepted restrictions and are rechecked after the configured lifetime. A damaged/unreadable cache fails review with an explicit error; it does not silently trigger a complete paid rebuild. Clear it with the authenticated refresh command.

`policy.ai.cache` reports `hits`, `misses`, `deduplicated_components`, `models`, `oldest_checked_at`, `next_refresh_at` and any persistence error. Timestamps are Unix seconds in UTC. A full cache hit uses zero provider calls, zero new usage and zero fresh batches. Cache hits can still represent stale or incomplete knowledge; they never mean vulnerability-free software. Fix persistence errors before relying on reuse; newly checked items cannot survive restart if saving fails. The cache is bounded to 50,000 entries / 64 MiB and contains private dependency/security metadata; protect it like the saved SBOM. No credentials or request traffic are stored there.

Force a fresh review of the current SBOM and discard **all** cached entries:

```sh
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --fail-with-body --max-time 960 -X POST \
  http://127.0.0.1:9090/v1/refresh \
  --output filtr-refresh-report.json
```

In Docker, run the same command through the authenticated loopback admin API:

```sh
docker compose exec -T filtr sh -ec '
  printf "header = \"Authorization: Bearer %s\"\n" "$FILTR_ADMIN_TOKEN" |
    curl --config - --noproxy "*" --fail-with-body --max-time 960 -X POST \
      http://127.0.0.1:9090/v1/refresh
' > filtr-refresh-report.json
```

Refresh uses the installed inventory and saved leaderboard (or model override); it does not rewrite package versions. It shares the upload lock, returns the resulting policy, and continues processing if the client disconnects. It returns `409` if no SBOM is installed or another update is running. Static mappings serve during review. Recreate containers after changing `.env`; never print the expanded Compose configuration containing credentials.
