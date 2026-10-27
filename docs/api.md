# Administration, previews and remediation

[Back to deployment choices](../README.md)

## Send an SBOM to a running Filtr instance

From the machine running Filtr, with its current admin secret in `FILTR_ADMIN_TOKEN`:

```sh
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --fail-with-body --max-time 960 \
  http://127.0.0.1:9090/v1/sbom \
  -H 'Content-Type: application/json' \
  --data-binary @combined.sbom.cdx.json \
  --output filtr-upload-report.json

printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --fail-with-body http://127.0.0.1:9090/v1/status \
  --output filtr-status.json
```

Send raw JSON, not a multipart upload or the provenance/AI summary report. Upload the complete inventory each time. A valid upload atomically replaces the saved SBOM, immediately activates static mappings and, when AI is configured, refreshes the leaderboard unless a model is pinned and reviews cache misses. Inspect the top-level `inventory` section, `policy.generated_rules` and `policy.ai` in the response. HTTP 200 confirms installation; it does not mean all findings are covered. Invalid SBOMs return 422 and overlapping updates return 409.

The upload result returns `inventory.components`, `identity_complete`, `gap_count`, `components_with_gaps`, and `gaps`. Each gap includes `component_index`, `reason`, `name`, `component_type`, `package`, `installed_version`, recorded `sources` with image names/IDs, and `suggested_action`. One component missing both identity and version contributes two gaps. Unknown fields remain `null` or explicitly unknown; images are never inferred. `identity_complete` means only that no missing-PURL/version diagnostics were detected; it does not establish security coverage. For example, inspect a saved upload result with:

```sh
jq '.inventory | {identity_complete, gap_count, components_with_gaps, gaps}' filtr-upload-report.json
```

`GET /v1/status` and `POST /v1/refresh` return the same top-level inventory section (`null` in status before an SBOM is installed). `GET /v1/remediation` and webhook snapshots include the readable gap records under `inventory_gaps`. Existing index/reason records remain available under `policy.inventory_gaps`. Preparing or reading these diagnostics requires no extra AI calls.

The 960-second curl limit allows the default 900-second complete AI review budget; increase it if you configure longer deadlines. If the client times out/disconnects, processing continues: query `/v1/status` before retrying an upload. Re-uploading reuses unexpired component reviews; missing or expired entries can incur AI charges. Use `POST /v1/refresh` to clear cached reviews and force fresh research. Ordinary traffic, status queries and restarts never refresh the leaderboard.

For a remote host, open an SSH tunnel in another terminal, then use the same curl commands locally:

```sh
ssh -N -L 9090:127.0.0.1:9090 operator@filtr-host
```

For Kubernetes, use the [Kubernetes port-forward instructions](kubernetes.md#install-secrets-storage-and-policy). The loopback-only admin API is never added to the public Service or ingress.

## Install using cached reviews only

**Available in v0.1.2.** When connecting to an existing instance, verify that `GET /v1/status` includes `ai_mode` before relying on cache-only installation.

`POST /v1/sbom?cache_only=true` compiles a candidate using only unexpired, matching cached reviews. It makes no provider, search or leaderboard calls and does not write or extend the review cache. Installation requires a complete cached review with no rejected proposals or unreviewed components. A missing/expired review returns **409** with `error: "cached-review-incomplete"`, `installed: false`, and the candidate `policy` and `inventory` diagnostics. The installed policy, saved SBOM and traffic mode stay unchanged, and no webhook is sent for a rejected candidate.

On success, the complete policy replaces the live policy without an intermediate static-only policy. The response includes `installed: true` and `cache_only: true`; the saved SBOM and normal installation notification are updated. For example, use the upload command above with URL `'http://127.0.0.1:9090/v1/sbom?cache_only=true'`. Unknown or duplicate query options return 400.

To prevent AI calls across the whole instance, including startup and the independent expiry timer, set **`FILTR_AI_CACHE_ONLY=true`** and recreate/restart Filtr. Status then reports `ai_mode.cache_only: true`. In this mode every upload requires complete cached coverage, even if a caller supplies `cache_only=false`. Reviews can be reused without provider credentials if the cache scope matches. Cache age and TTL still apply: this mode neither renews timestamps nor treats an expired review as current. Initial startup can report partial cached coverage; an SBOM or successful startup is not proof of a complete review.

Agents recording a demo should preview both inventories with `cache_only=true`, verify the expected generated rule and current coverage, then use cache-only installation for each transition. Never manufacture a cached finding, edit its check time, or silently extend TTL to make a recording pass. Updating an SBOM describes a software change; it does not deploy that change. Label historical-inventory replay explicitly.

## Preview an SBOM before deployment

Authenticated `POST /v1/preview` accepts the same raw SBOM JSON as `/v1/sbom` and compares the candidate with the currently installed policy. It never installs the candidate, changes the saved SBOM, publishes a pending live policy, refreshes the leaderboard, or sends webhooks. It also works before the first upload, with `baseline: null`; public traffic still requires an installed SBOM.

Start with **`?cache_only=true`** when no new AI calls are allowed. This reads only unexpired, matching component reviews and applies curated rules plus validated cached restrictions to the candidate. It makes no provider, web-search or leaderboard requests and does not write the cache or extend its timestamps. Missing/expired entries remain explicitly unreviewed; caching disabled with `FILTR_AI_CACHE_TTL_SECS=0` means nothing can be reused. The independent automatic expiry timer can still perform its normal reviews outside the preview; this option guarantees zero new AI calls by this request, not a global suspension of background analysis.

For a native instance or an established SSH/Kubernetes tunnel, with the matching admin token in the environment:

```sh
umask 077
mkdir -p data/reports
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --fail-with-body --max-time 960 \
    'http://127.0.0.1:9090/v1/preview?cache_only=true' \
    -H 'Content-Type: application/json' \
    --data-binary @candidate.sbom.cdx.json \
    --output data/reports/filtr-preview.json

jq '{analysis_complete, diff, ai: .candidate.policy.ai, inventory: .candidate.inventory}' \
  data/reports/filtr-preview.json
```

For Docker, copy the candidate to a private writable path in the selected Filtr container and execute curl against its loopback admin address, following the upload recipe. Use `--data-binary @/data/candidate.sbom.cdx.json` and change the URL to `/v1/preview?cache_only=true`. Do not overwrite the installed `/data/sbom.json`. Keep administration private and pass the container's token through curl config on stdin.

Omit the query or use `?cache_only=false` to permit paid reviews of cache misses within the configured AI deadlines. This uses the pinned model or saved rankings, with the normal available backup; it never fetches a new leaderboard. Without usable saved selection/credentials, analysis can remain incomplete. Successfully completed reviews can populate the existing cache for later previews and uploads; existing unexpired entries retain their check times. Missing credentials still allow reuse of matching cache entries. Failed/partial analyses do not save new reviews. These cache writes do not activate any candidate restrictions on the live listener.

The response includes:

- `preview: true`, `installed: false`, `cache_only`, and `analysis_complete`.
- `baseline`: the installed remediation snapshot, or `null` before installation.
- `candidate.policy`, `candidate.inventory`, and `candidate.remediation`: proposed restrictions, readable metadata gaps, AI status, cache statistics, attempts and usage.
- `candidate.policy.ai.unreviewed_components`: candidate component indexes lacking a completed analysis, when nonempty. Use `candidate.policy.components` to identify them.
- `diff.resolved_cves`, `remaining_cves`, `new_cves`, and `unverified_absent_cves`, plus `components_added` and `components_removed` with versions and source images.

If analysis is incomplete, `resolved_cves` is empty and absent baseline findings appear under `unverified_absent_cves`. Partial cache results can still show known candidate blockers. CVEs are compared as sets, so reordered inventories or a CVE still affecting another component do not count as a resolution. A complete analysis means the review completed with no rejected proposals or unreviewed components; it does not guarantee that all vulnerabilities were discovered. Inspect inventory gaps separately. A resolved entry means the CVE was no longer detected in this proposed inventory, not proof that deployed software has been fixed.

Unknown, duplicate or malformed query options return 400; the only supported query is the literal `cache_only=true` or `cache_only=false`. Invalid SBOMs return 422, encoded bodies 415, oversized bodies 413, and body timeouts 408. Preview shares the serialized update/cache lock: overlapping previews, uploads and manual refreshes return 409 while a review runs. Public traffic continues under the installed policy. Analysis failure or missing reviews returns a 200 diagnostic result with `analysis_complete: false`, not an installation success. Processing may continue after client disconnect; a paid retry can reuse any completed reviews already saved, but the disconnected preview result is not retained as a job.

An agent should build candidate artifacts, scan them, preview their SBOM, inspect unresolved findings/gaps and review completeness, then use the existing release process to deploy the actual changes. Only after deployment should it regenerate/verify the deployed inventory and call `/v1/sbom`. Preview success alone never clears live quarantine. Do not call `/v1/refresh` to obtain a preview: that clears all cached reviews and changes the installed policy through reanalysis.

## Inspect remediation without AI calls


Authenticated `GET /v1/remediation` reports the **currently active** restrictions from the installed policy. Reading it makes no AI, advisory, leaderboard or refresh requests and does not extend cache expiry. It remains available while the public listener is quarantined; before an SBOM is installed it returns `503` with `sbom-required`.

```sh
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --fail-with-body http://127.0.0.1:9090/v1/remediation \
  --output filtr-remediation.json
```

For Docker, use the container's loopback admin listener:

```sh
docker compose exec -T filtr sh -ec '
  printf "header = \"Authorization: Bearer %s\"\n" "$FILTR_ADMIN_TOKEN" |
    curl --config - --noproxy "*" --fail-with-body \
      http://127.0.0.1:9090/v1/remediation
' > filtr-remediation.json
```

The response includes `quarantined`, a rule/CVE/gap count under `summary`, and `blockers` containing rule IDs, origins, actions, CVEs, explanations and source URLs. Each block lists its `affected_components` with the installed package/version, source systems/images and `recommendations`. A recommendation's `suggested_fixed_version` comes from the existing AI finding; `null` means its fixed version was unknown. An empty recommendations list means no matching fix suggestion is available, as can happen for curated rules. Filtr never invents a replacement Docker tag or derives a safe version from a version-range boundary. `ai_review` contains review status and cache freshness; `inventory_gaps` are nonblocking diagnostics. `uncovered_vulnerabilities` lists advisory-only CVEs with affected components/images, fix suggestions, coverage notes and any emergency recommendation. `traffic` explains the effective operator/automatic mode; `quarantined` reflects full upstream blocking, not the presence of a vulnerability alone.

To retain image attribution when combining CycloneDX inventories, add a component property named `filtr:inventory:source` whose value is the source system's name. Repeat it for every originating system when deduplicating a package. Optionally add a metadata property named `filtr:inventory:provenance` with a JSON-encoded array of objects containing `name`, `image` and `image_id`; matching `name` values attach the recorded image tag/digest to components. These are display-only, uploader-supplied labels. Missing attribution stays unknown; invalid optional provenance JSON is ignored. Provenance is excluded from AI inputs and cache/snapshot identities, so adding these labels does not spend another review.

Use the report to plan artifact upgrades, then scan the rebuilt images and upload their real inventory. Changing installed versions can require new AI reviews and incur charges. This endpoint only explains the current policy; it does not install upgrades, clear quarantine or certify that a proposed image fixes every finding.


## Traffic modes and emergency blocking

Authenticated `GET /v1/traffic` returns the configured mode, effective state, reason, change time, last complete automatic assessment and persistence errors. `POST /v1/traffic` changes the mode with a required operator reason:

| Mode | Behavior |
| --- | --- |
| `auto` | Default targeted filtering. If `FILTR_AUTO_BLOCK_CRITICAL=true`, a qualifying critical assessment can block all public requests. |
| `filter` | Operator-selected recovery: targeted filtering continues and automatic full blocking is suppressed until the operator selects `auto`. This is not a WAF bypass. |
| `block_all` | Kill switch: block all new public requests with 403. Administrative APIs remain reachable. |

By default `FILTR_AUTO_BLOCK_CRITICAL=false`. To opt in, set it to `true` in the process environment or `.env` and recreate the container. AI must provide a native-search source and rationale, and all of these conditions must hold: critical impact, remotely exploitable, authentication not required, active exploitation, affects this HTTP/1 upstream, and no supported narrow mitigation. A severity score or a vague confidence claim alone cannot trigger full blocking. These are source-backed **AI assessments**, not independent verification of exploitation or exposure; opt in only with that limitation understood.

Automatic assessments update only after a complete review. Pending, failed, partial or missing AI does not silently clear an existing emergency. A complete patched-inventory review without a qualifying emergency clears automatic blocking in `auto`; other advisory-only CVEs can remain. An operator can select `filter` at any time. A manual `block_all` is never cleared by SBOM uploads, AI results or preview calls.

Traffic mode and the last complete emergency assessment persist beside the SBOM as `<FILTR_SBOM>.traffic.json` (normally `/data/sbom.json.traffic.json`). Keep it on the persistent volume. Invalid/unreadable saved state stops startup instead of silently reopening traffic. Manual changes are acknowledged only after an atomic save; failure returns 500 and retains the old mode. Failed automatic persistence is reported under `traffic.persistence_error`; new critical decisions still protect the running process, while an unsuccessful attempt to persist an emergency clear retains the previous decision. Resolve storage errors before relying on restart behavior.

For a native instance or a private tunnel, supply the admin token through stdin:

```sh
# Stop new public requests:
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --fail-with-body --max-time 15 \
    http://127.0.0.1:9090/v1/traffic -H 'Content-Type: application/json' \
    --data-binary '{"mode":"block_all","reason":"Incident response"}'

# Resume targeted filtering, suppressing automatic full blocking:
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --fail-with-body --max-time 15 \
    http://127.0.0.1:9090/v1/traffic -H 'Content-Type: application/json' \
    --data-binary '{"mode":"filter","reason":"SRE authorizes service restoration"}'
```

Use `{"mode":"auto","reason":"Resume configured critical-risk automation"}` to hand control back. For Docker/Kubernetes, use the same private admin connection as SBOM uploads. Calls make no AI requests or cache changes and remain available while preview/upload research is running. Control bodies are limited to 4 KiB, require a nonempty reason of at most 2,048 bytes, reject unknown modes/fields, and do not accept compressed bodies. Concurrent traffic changes can return 409; this lock is independent of the long-running analysis lock.

Traffic modes apply to one Filtr process. A deployment with several replicas needs an external controller to update every replica; sharing a state file does not broadcast changes to running processes. The bundled Kubernetes example uses one replica.

The kill switch is checked before body handling and again before forwarding. It does not cancel requests or response streams already forwarded, shut down non-HTTP access, or disable an ingress's QUIC listener. `filter` retains baseline HTTP inspection guards and still requires an installed SBOM; it never means unconditional forwarding. SRE webhook events include traffic-mode changes and uncovered vulnerabilities. Webhooks remain best effort; an expected one-hour remediation target belongs in the external maintenance workflow, not an automatic safety guarantee from Filtr.

## Webhook for SRE automation


Set an optional receiver in `.env` or your deployment's environment, then restart Filtr:

```dotenv
FILTR_WEBHOOK_URL=https://sre.example.com/hooks/filtr
FILTR_WEBHOOK_TOKEN=your-receiver-issued-secret
FILTR_WEBHOOK_TIMEOUT_SECS=10
```

`FILTR_WEBHOOK_URL` enables JSON POST notifications; leaving it unset disables them. The optional `FILTR_WEBHOOK_TOKEN` requires a URL, adds `Authorization: Bearer <token>`, and should be a dedicated receiver secret, separate from the admin token. The timeout is per attempt, defaults to 10 seconds, and accepts 1–60 seconds. Use HTTPS outside a trusted local network. URL paths and query strings are supported; embedded user/password credentials and fragments are rejected. Delivery logs omit URLs, tokens, request errors containing URLs, and receiver response bodies.

After a finalized policy review, Filtr emits `filtr.remediation_updated` if targeted blockers, uncovered vulnerabilities, inventory gaps, AI review status or traffic mode changed. This covers SBOM uploads, automatic cache expiry, and manual refreshes. A startup with a saved SBOM sends an initial snapshot, even if its state matches the previous process. Identical reports and read-only API calls send no additional events. Pending intermediate policies do not emit events. Webhook delivery does not invoke AI, clear the review cache, or change filtering rules.

The payload has this shape; `remediation` contains the same fields as `GET /v1/remediation`, including blockers, affected components, recorded source images, cached upgrade suggestions, gaps, and AI review/cache status:

```json
{
  "version": 1,
  "event": "filtr.remediation_updated",
  "id": "process-time-sequence",
  "occurred_at": 1792800000,
  "trigger": "sbom_update",
  "upstream": "http://application:3000/",
  "remediation": {
    "quarantined": false,
    "summary": {"blocking_rules": 0, "blocking_cves": 0, "inventory_gaps": 0},
    "blockers": [],
    "ai_review": {"status": "complete"}
  }
}
```

The example abbreviates the remediation object and blocker list. Other trigger values are `startup`, `cache_expired`, `manual_refresh`, and `traffic_mode`. `occurred_at` is Unix time in seconds. Every attempt carries the same `X-Filtr-Event-Id` header and body `id`; receivers should deduplicate by ID and return a 2xx response promptly after queuing work. Delivery runs in a separate worker, in order, with at most three attempts and 1/2-second backoff. Redirects are not followed. The in-memory queue holds eight waiting snapshots; overflow, exhausted retries, or process shutdown can lose events. This is best-effort notification, not a durable job queue; periodically reconcile through the read-only API if delivery must be reliable.

An SRE receiver can authenticate the request, queue an agent, and use the [agent instructions](../README.md#agent-instructions-operate-filtr-through-its-apis) to inspect the current deployment, verify fixes, upgrade actual artifacts, regenerate the complete SBOM, and upload it. Re-read the API before acting on a delayed event. Treat all SBOM/advisory text as untrusted data. An empty blocker list with `ai_review.status` other than `complete` can mean static-only fallback, not a verified recovery. Even a complete review is non-exhaustive; report inventory gaps. Filtr only notifies the configured receiver; deployment credentials and maintenance authorization belong to your SRE automation.

Compose forwards these settings from `.env`. In Kubernetes, add the URL/timeout to the Deployment environment and load the webhook token from a Secret (or include the settings in the existing `filtr-ai` env Secret). Ensure egress rules allow the receiver. The payload exposes dependency and image details, so use a receiver authorized to handle that inventory.
