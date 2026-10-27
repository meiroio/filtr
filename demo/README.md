# Record Filtr's targeted filtering in two terminal tabs

The main presentation replays two inventories in front of the existing local Betterpipes application: a vulnerable Bun inventory with a previously cached, narrowly scoped Brotli rule, then a patched inventory. It sends harmless plain and Brotli-encoded requests to `POST /readyz` and validates real responses and forwarding counters. **This is an inventory policy replay. Betterpipes keeps running patched Bun 1.4.4; the presenter does not downgrade, exploit or deploy software.** In production, install the patched software before uploading its actual inventory.

Use an authorized local demonstration instance. The presenter changes its installed policy, so do not point it at production. It requires Docker, host Python 3 and curl, plus sh/curl in the Filtr container. Administration stays on container loopback `127.0.0.1:9090`; the token stays inside the container. The independent [baseline checker](#one-command-check) remains read-only.

## Prepare the replay without new AI calls

Use a Filtr build with `FILTR_AI_CACHE_ONLY=true`, `GET /v1/status` reporting `ai_mode.cache_only: true`, and strict `POST /v1/sbom?cache_only=true` installation. Global cache-only mode prevents provider, web-search, leaderboard and background AI calls. A strict upload returns 409 without changing the installed inventory if its cached analysis is incomplete. This behavior is required; the script does not fall back to ordinary uploads or `/v1/refresh`.

Use the actual deployed inventory for the patched and restoration snapshots. For the vulnerable phase, use either a historical inventory with complete cached coverage or a clearly labelled candidate copied from the current full inventory with only Bun's version/PURL changed. For a candidate, update its evidence metadata to say that the running software remains patched; retain all other application and Docker dependencies. The vulnerable candidate must have a cached AI rule tied to Bun and the selected CVE that matches incoming `Content-Encoding: br`; the patched snapshot must no longer report that CVE. The presenter does not create rules, invent source evidence or change cache timestamps. Missing rules or missing/expired reviews stop the demonstration.

The following paths are examples: put your previously generated inventories there or substitute their real paths.

```sh
python3 demo/present.py live \
  --vulnerable-sbom data/demo-input/vulnerable.sbom.json \
  --patched-sbom data/demo-input/patched.sbom.json \
  --preflight-only
```

Preflight reads status, privately saves the original installed SBOM, and performs cache-only previews of the vulnerable, patched and original inventories **before any policy change**. All three must have complete cached reviews, cache hits, zero misses, zero new attempts and at least ten minutes of cache validity remaining. It checks that the saved original matches the active inventory, the vulnerable candidate has the intended incoming-Brotli rule, the patched candidate no longer reports the selected CVE, and neither candidate fully blocks traffic. Unknown coverage is a failure to prepare this recording, never proof of safety. If a required review is missing, arrange a separately authorized review before retrying; this command will not purchase one.

Defaults: container `filtr-betterpipes-filtr-1`, origin `http://127.0.0.1:18080`, installed container file `/data/sbom.json`, CVE `CVE-2026-111497`, and harmless `POST /readyz` returning 200. Use `--container`, `--url`, `--installed-sbom`, `--cve`, `--brotli-path` and `--brotli-status` for another verified setup. Choose a read-only endpoint that accepts a POST body; both the plain and compressed request must be harmless. Use a quiet local instance so unrelated traffic does not invalidate the counter checks.

## Two-tab terminal presentation

Use two terminal tabs in this repository. The presenter uses Python's standard library, including `curses` for the slide tab; no package installation is needed on the supported local macOS/Linux terminal setup. Use a large font and about **100 columns × 28 rows** (minimum 72 × 24).

**Tab 1 — story and slides:**

```sh
python3 demo/present.py slides
```

- Space, Enter or Right: next slide; Left: previous slide.
- `1`–`6`: jump directly to a section.
- `N`: toggle narration from the four-minute script.
- `Q`: quit and restore the terminal. Resizing redraws the slide.

**Tab 2 — live policy replay:**

```sh
python3 demo/present.py live \
  --vulnerable-sbom data/demo-input/vulnerable.sbom.json \
  --patched-sbom data/demo-input/patched.sbom.json
```

Each step displays **WHAT**, **WHY** and **EXPECT** before it runs. Enter runs it; **OBSERVED** describes its validated result. Enter again explains the next step. `Q` exits at either prompt. There are six steps:

1. Install the vulnerable inventory through the strict cache-only API.
2. Send a normal POST: expect 200 and an upstream forwarding increment.
3. Send the same text encoded as Brotli: expect 403 from the exact cached CVE rule, with no forwarding increment.
4. Install the patched inventory through the same strict API.
5. Repeat the identical Brotli request: expect 200 and upstream forwarding.
6. Repeat the normal POST: expect 200 again.

The four public responses are **200 → 403 → 200 → 200**. The two admin installations also return 200. No traffic-mode API is called, and other protections remain enabled. An unexpected response stops the presentation. Bodies, SBOM snapshots and reports stay in a private directory under ignored `data/demo-live/`; the terminal does not show application bodies, credentials or raw security reports.

A successful replay leaves the patched inventory installed. After an error, `Q`, or ordinary Ctrl-C following the first upload, the presenter attempts to restore the saved original inventory using the same strict cache-only API and verifies its component inventory. If restoration fails, it prints a recovery command. A force-killed process or lost Docker connection cannot promise automatic cleanup; use the saved path from that run:

```sh
python3 demo/present.py restore \
  --container filtr-betterpipes-filtr-1 \
  --sbom data/demo-live/take-REPLACE/original.sbom.json
```

Restoration also requires usable cached reviews and global cache-only mode. It never silently enables paid reviews, modifies cache timestamps, or disables filtering. The run's private `manifest.json` records whether the replay completed or the original inventory was restored.

Follow the [English narration](../docs/video-script-en.md):

| Time | Tab | What to show |
| --- | --- | --- |
| 0:00–0:55 | 1, slide 1 | Production Node/Bun patching experience |
| 0:55–1:30 | 1, slide 2 | Request flow, SBOM and targeted filtering |
| 1:30–2:15 | 2 | Inventory policy replay; four public requests |
| 2:15–2:50 | 1, press `4` | Agent workflow, preview and cache |
| 2:50–3:35 | 1, slide 5 | Simple mode and Kubernetes deployment |
| 3:35–4:00 | 1, slide 6 | Limits, repository and invitation |

Slide 3 is a cue for switching tabs, not recorded proof. All live results come from HTTP requests; missing cache or rules produce a failure, never simulated success.

For text export, use `python3 demo/present.py slides --plain` or add `--notes`. Add `--auto` to the fully specified live command for a rehearsal without keypress pauses; it performs the same policy changes and checks.

## One-command check

From the repository root:

```sh
python3 demo/check.py
```

Defaults target the local Betterpipes demo: container `filtr-betterpipes-filtr-1` and public origin `http://127.0.0.1:18080`. For another running composition:

```sh
python3 demo/check.py \
  --container your-filtr-container \
  --url http://127.0.0.1:8080
```

The application root must normally return 200. Run this functional check on an instance you are authorized to test; it is not a load test or a complete application regression suite.

The checker verifies:

| Check | Expected result |
| --- | --- |
| Authenticated `/livez` and `/healthz` on the private admin listener | 200 |
| Public `GET /` | 200, forwarded to the application |
| Public `GET /.env`, `GET /.git/config` | 403 with Filtr's `restricted-target` response |
| Public `GET /%2e%2e/etc/passwd` with path normalization disabled | 403 with the same Filtr rejection |
| Public `GET /` again | 200; the rejected requests did not take the application offline |
| Counter changes | At least 5 seen, 2 proxied, 3 blocked; no new upstream errors |

It exits nonzero on failure. Other clients can increase counters during the check; use a quiet local instance when recording. Comparing status before and after also shows whether the installed AI review metadata changed. The cache counters and usage in status describe the **last review**, not new work caused by reading that report.

Complete status/remediation JSON and HTTP response bodies are saved in a new private directory under ignored `data/demo-check/`; only a short summary is printed. These files can contain application and dependency details. Keep them off screen and out of Git. The check issues no Filtr AI requests. On an ordinary instance without global cache-only mode, the independent cache-expiry timer can perform its normal paid analysis; unchanged metadata during a short check is an observation, not a provider billing audit.

`GET /v1/traffic` is checked for availability. A 404 is reported as an older-build capability limit, without trying a POST. The checker does not test kill-switch behavior or claim that newer preview APIs are present.

## Independent baseline path checks

These public requests discard response bodies, so application data does not fill the terminal:

```sh
curl --noproxy '*' --silent --show-error --max-time 15 \
  --output /dev/null --write-out 'Normal request: HTTP %{http_code}\n' \
  http://127.0.0.1:18080/

curl --noproxy '*' --silent --show-error --max-time 15 \
  --output /dev/null --write-out 'Secret-file probe: HTTP %{http_code}\n' \
  http://127.0.0.1:18080/.env

curl --noproxy '*' --silent --show-error --max-time 15 --path-as-is \
  --output /dev/null --write-out 'Encoded traversal probe: HTTP %{http_code}\n' \
  'http://127.0.0.1:18080/%2e%2e/etc/passwd'

curl --noproxy '*' --silent --show-error --max-time 15 \
  --output /dev/null --write-out 'Normal request again: HTTP %{http_code}\n' \
  http://127.0.0.1:18080/
```

For these independent baseline checks, the sequence is **200, 403, 403, 200**. The checker additionally validates rejection bodies and counters. This demonstrates baseline filtering and continued forwarding; it does not demonstrate an AI-generated CVE rule or patch deployment.

Inspect the selected containers without dumping credentials:

```sh
docker ps --filter label=com.docker.compose.project=filtr-betterpipes \
  --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'

docker exec filtr-betterpipes-filtr-1 filtr --version

docker inspect --format '{{.Name}} {{json .NetworkSettings.Ports}}' \
  filtr-betterpipes-filtr-1 filtr-betterpipes-betterpipes-1

docker network inspect --format '{{.Name}} internal={{.Internal}}' \
  filtr-betterpipes_backend filtr-betterpipes_egress
```

The intended route is host port 18080 → Filtr port 8080 → Betterpipes port 8081 over the internal backend network. Betterpipes and its database/search services should have no published host bindings in this composition. An exposed image port such as `80/tcp` alone is metadata, not a host binding or proof of the app's actual listen port. The admin port should not be published. The separate egress network lets Filtr contact its AI provider.

Read cached reports through container loopback. The token stays inside the container and travels to curl through stdin:

```sh
umask 077
mkdir -p data/reports
docker exec filtr-betterpipes-filtr-1 sh -ec '
  printf "header = \"Authorization: Bearer %s\"\n" "$FILTR_ADMIN_TOKEN" |
    curl --config - --noproxy "*" --fail --silent --show-error --max-time 15 \
      http://127.0.0.1:9090/v1/remediation
' > data/reports/demo-remediation.json
```

Use `/v1/status` in the same command for the full policy/counters. Do not display `.env`, expanded Compose configuration, a full `docker inspect`, shell tracing or raw security reports in a public recording.

## Candidate fixes and emergency controls

For a deployed release supporting these APIs, an authorized maintenance agent should first read remediation, upgrade the actual artifacts, generate their candidate SBOM and call [`POST /v1/preview?cache_only=true`](../docs/api.md#preview-an-sbom-before-deployment). That preview does not install the inventory or spend new AI calls by that request. Cache misses mean incomplete analysis, not a clean bill of health. Deploy approved artifacts before uploading their verified deployed inventory.

[`POST /v1/traffic`](../docs/api.md#traffic-modes-and-emergency-blocking) can deliberately interrupt service. Demonstrate it only on an authorized disposable instance: record the previous mode, select `block_all`, verify a normal request returns 403, then restore the previous mode and recheck normal and blocked paths. Selecting `filter` retains targeted protections while suppressing automatic full blocking; it is a deliberate operator choice. This checker never changes mode. Do not use `/v1/refresh` to prepare a recording: it clears cached reviews and can trigger full-inventory charges.

See the [four-minute English video script](../docs/video-script-en.md). Keep local observations and sensitive reports under `data/`; public documentation should describe reproducible behavior rather than private deployment history.
