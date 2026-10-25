# Build, Docker and development

[Back to deployment choices](../README.md)

Commands in this guide run from a source checkout, not the extracted binary archive.

```sh
git clone --branch v0.1.0 --depth 1 https://github.com/meiroio/filtr.git filtr-source
cd filtr-source
```

## Run

Install a current stable Rust toolchain and build:

```sh
cargo build --release --locked --bin filtr --examples
```

Point Filtr at your existing application origin. For a local demo, run `./target/release/examples/upstream` in another terminal; it listens on port 3000.

```sh
export FILTR_ADMIN_TOKEN="$(openssl rand -hex 64)"
# Supply OPENAI_API_KEY and/or ANTHROPIC_API_KEY through your environment/secret manager.
# Without either key, only static mappings apply; policy.ai.status is not_configured.
# Optional: restrict the primary provider (otherwise choose the best configured provider).
# export FILTR_AI_PROVIDER=anthropic
# OPENAI_API_KEY also enables the gpt-5.6-luna backup for either primary provider.
./target/release/filtr --upstream http://127.0.0.1:3000 &
FILTR_PID=$!

# Public requests return 503 until a valid SBOM is installed.
curl -i http://127.0.0.1:8080/

# Activate the example Log4j policy; substitute your application's real SBOM.
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --fail-with-body http://127.0.0.1:9090/v1/sbom \
  -H 'Content-Type: application/json' \
  --data-binary @examples/sbom.cdx.json

# Benign requests forward unless an operator or opted-in emergency decision blocks them.
curl -i http://127.0.0.1:8080/hello

# Harmless detection test: 403, never reaches upstream.
curl -i http://127.0.0.1:8080/ -H 'X-Test: ${jndi:ldap://example.invalid/test}'

# Includes curated/generated rules, AI review, CVE coverage, limits and counters.
printf 'header = "Authorization: Bearer %s"\n' "$FILTR_ADMIN_TOKEN" |
  curl --config - --noproxy '*' --fail-with-body http://127.0.0.1:9090/v1/status

kill "$FILTR_PID"
```

The public listener defaults to `127.0.0.1:8080`; administration uses `127.0.0.1:9090`. Every admin endpoint requires a **64-byte random secret (512 bits), encoded as exactly 128 hexadecimal characters**. Generate it with `openssl rand -hex 64` and supply it through `FILTR_ADMIN_TOKEN`. Provider API keys retain the format issued by their provider. Admin binding is restricted to loopback. For a remote machine, use an SSH tunnel.

Uploads are validated and compiled before activation, atomically saved to `data/sbom.json`, then published as an immutable policy through `ArcSwap`. Invalid uploads and persistence failures preserve the active policy. The saved SBOM is reloaded on restart; a corrupt saved SBOM stops startup. A request uses the policy available after its body has been read; requests already inspected can finish under their previous policy.

Static mappings activate immediately after persistence and serve traffic throughout AI review and backup attempts. The upload response waits for configured AI review to finish or reach its deadline. While waiting, `/v1/status` shows the current pending phase. Generated restrictions activate atomically only after a successful AI review. Missing credentials or failure of both the primary and available backup leave the static policy in place, with vulnerability coverage explicitly unknown. Each upload replaces the previous policy, including previous AI enhancements. Processing continues if the client disconnects. Concurrent uploads return 409 until the current upload and review finish.

## Docker

The [Dockerfile](https://github.com/meiroio/filtr/blob/v0.1.0/Dockerfile) uses a Rust build stage and a Debian runtime with CA certificates and curl for authenticated loopback probes. The runtime runs as UID/GID `10001`, handles SIGTERM, and exposes only public port 8080. The build context is restricted by [.dockerignore](https://github.com/meiroio/filtr/blob/v0.1.0/.dockerignore); local SBOMs, tokens and data are not copied into the image. Build for the CPU architecture used by your cluster:

```sh
docker build --pull -t filtr:0.1.0 .

# To publish for an amd64 Kubernetes cluster from any build machine:
export FILTR_IMAGE=ghcr.io/YOUR_ORG/filtr:0.1.0
docker buildx build --platform linux/amd64 -t "$FILTR_IMAGE" --push .
# For a mixed cluster, use --platform linux/amd64,linux/arm64.
```

### Local Compose demo

[compose.yaml](https://github.com/meiroio/filtr/blob/v0.1.0/compose.yaml) starts Filtr and the harmless Rust demo upstream. It reads your existing `.env` for credentials and overrides the upstream/listener addresses for the private Docker network. Only Filtr's public port is published, on host loopback; the demo origin and admin listener are not published. Docker Compose's [`env_file` setting](https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/) injects credentials at runtime.

Create `.env` from [.env.example](../.env.example) for a new checkout, or keep an existing configuration. Add your provider key(s) if using AI. Add an admin secret **only if one is missing**, then start:

```sh
# Create the template only if .env does not already exist:
test -e .env || cp .env.example .env
# Run this line once, only if FILTR_ADMIN_TOKEN has no value in .env:
printf '\nFILTR_ADMIN_TOKEN=%s\n' "$(openssl rand -hex 64)" >> .env
chmod 600 .env
docker compose up --build --detach --wait
docker compose ps

# 503 before the first SBOM has been installed.
curl -i http://127.0.0.1:8080/
```

Upload the bundled vulnerable Log4j inventory and save the result locally:

```sh
mkdir -p data
docker compose exec -T filtr sh -ec '
  umask 077
  cat > /data/upload.sbom.json
  printf "header = \"Authorization: Bearer %s\"\n" "$FILTR_ADMIN_TOKEN" |
    curl --config - --noproxy "*" --fail-with-body --max-time 960 \
      -H "Content-Type: application/json" \
      --data-binary @/data/upload.sbom.json http://127.0.0.1:9090/v1/sbom
' < examples/sbom.cdx.json > data/local-upload-report.json

# Inspect status without displaying credentials:
docker compose exec -T filtr sh -ec '
  printf "header = \"Authorization: Bearer %s\"\n" "$FILTR_ADMIN_TOKEN" |
    curl --config - --noproxy "*" --fail --silent http://127.0.0.1:9090/v1/status
'

curl -i http://127.0.0.1:8080/ -H 'X-Test: ${jndi:ldap://example.invalid/test}'
```

The attack marker should return 403 without reaching the demo origin. Uncovered AI findings are reported without blanket blocking by default; inspect `policy.generated_rules`, `policy.ai.discoveries`, and remediation `uncovered_vulnerabilities`. Inspect `/v1/traffic` if ordinary traffic is fully blocked. Without working AI, only static mappings remain active. A missing OpenAI key means Luna backup is unavailable, even when Anthropic is configured. Reviews use the real provider and can incur charges.

The environment template sets `FILTR_AI_TIMEOUT_SECS=300` and `FILTR_AI_REVIEW_TIMEOUT_SECS=900`. The upload examples and local Compose startup health check allow 960 seconds. Recreate Filtr after changing `.env`. A failed batch or deadline keeps the static policy active and is reported in `policy.ai.error` and `attempts`.

Upload your patched application's accurate SBOM with the same command to replace the demo policy. Targeted restrictions are rebuilt from the replacement inventory. A complete review can clear automatic emergency blocking in auto mode, but a manual block_all requires an explicit traffic-mode change. Re-uploading reuses unexpired entries; only cache misses require AI calls. `docker compose restart filtr` rereads environment already present in that container and reuses the saved leaderboard; use `docker compose up -d --force-recreate filtr` after editing `.env` so Docker injects the new values. Unexpired cached reviews survive restart; missing/expired entries can trigger provider calls.

Use `docker compose down` to stop the demo while retaining its policy volume. `docker compose down --volumes` also deletes the saved local demo SBOM, leaderboard snapshot and review cache. Set `FILTR_PUBLIC_PORT=18080` in `.env` if host port 8080 is occupied, and use that port in the curl examples. Avoid printing `docker compose config` or container environment/inspect output containing credentials; use `docker compose config --quiet` for validation.

### Existing Docker upstream

The following local example assumes an existing Docker network `app-network` with the protected application reachable as `app:3000`. Set `FILTR_ADMIN_TOKEN` using `openssl rand -hex 64` first. Supply provider keys through the environment if desired:

```sh
docker run -d --name filtr --network app-network \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -p 127.0.0.1:8080:8080 \
  --mount type=volume,source=filtr-data,target=/data \
  -e FILTR_ADMIN_TOKEN -e OPENAI_API_KEY -e ANTHROPIC_API_KEY \
  -e FILTR_AI_PROVIDER -e FILTR_UPSTREAM=http://app:3000 \
  filtr:0.1.0

# Admin stays on container loopback; write and upload as the runtime user.
docker exec -i filtr sh -ec '
  umask 077
  cat > /data/upload.sbom.json
  printf "header = \"Authorization: Bearer %s\"\n" "$FILTR_ADMIN_TOKEN" |
    curl --config - --noproxy "*" --fail-with-body --max-time 960 \
      -H "Content-Type: application/json" \
      --data-binary @/data/upload.sbom.json http://127.0.0.1:9090/v1/sbom
' < combined.sbom.cdx.json
```

For this command, configure your **host's existing HTTPS proxy** to forward to `http://127.0.0.1:8080`. If that proxy is another container, connect it to `app-network` and configure its backend as `http://filtr:8080`; its own `localhost` cannot reach Filtr. For an entry point on another host, bind port 8080 to the Docker host's private interface and restrict it to that entry point. [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/) determines which host addresses can reach a container port.

Remove the application's direct public port mapping and old proxy routes after switching the entry point. Limit access to its private network to the services that need it. The bundled Compose file always sets `FILTR_UPSTREAM=http://origin:3000` for the demo; changing that value in `.env` alone will not replace it. For your application, edit the Compose service's `environment.FILTR_UPSTREAM`, attach Filtr to the application's network and remove the demo `origin`/`depends_on` configuration.

Publishing Docker port 9090 would not make the loopback-only admin listener accessible. Use `docker exec` as above. `/data` must be writable by UID/GID 10001 and persisted to retain both the SBOM and its leaderboard snapshot. Docker's health check reports admin responsiveness even before an SBOM is installed; public requests still return 503 until installation.

## Validation and performance

```sh
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo run --release --locked --example inspect_bench -- 100000
```

Rust tests use local listeners and mock leaderboard/provider services; they need no AI credentials or external network. Installer unit tests use local metadata. Docker installer fixtures download base images, OS packages and Express during image builds, then test local serving with a container-only systemctl adapter; they do not call AI providers. They cover request blocking/forwarding, HTTP framing, policy replacement and persistence, SBOM normalization, source-backed AI discovery, AI batching and validation, leaderboard lifecycle, provider fallback, model overrides, persistent cache reuse and invalidation, automatic expiry and manual refresh, `.env` loading and authenticated administration.

The benchmark prints nanoseconds per inspection and MiB/s for fixed inputs on one thread. It excludes HTTP parsing, allocation of request bodies, upstream latency, response streaming, SBOM parsing and catalogue compilation. It is not an end-to-end requests-per-second result; measure your actual workload before assigning a capacity target.

## Memory safety and dependency checks

All first-party Rust targets, including the binary and examples, compile with Cargo's `unsafe_code = "forbid"`; the library also has a crate-level prohibition. First-party unsafe blocks/functions/implementations are not permitted. Network/provider parsing, forwarding headers, policy availability, batch/cache bookkeeping, webhook serialization and signal registration use checked errors or explicit fallback paths. Test assertions and parsing fixed built-in URL literals can still panic; those are not memory-unsafe Rust operations, and this is not a claim of a panic-free process.

Third-party dependencies are used through their safe APIs and reviewed on a best-effort basis. Rustls supplies the TLS layer, but its crypto backend, Tokio, platform bindings and other transitive dependencies can contain unsafe Rust and native code. Forbidding unsafe in Filtr does not audit those implementations or prove the entire dependency tree memory-safe. Keep patched dependencies, review new features/dependencies, and run `cargo audit` against `Cargo.lock` for known RustSec advisories. That audit is a development check; Filtr's runtime vulnerability discovery remains AI-only. A clean advisory audit or a text search for unsafe is not a dependency soundness proof.
