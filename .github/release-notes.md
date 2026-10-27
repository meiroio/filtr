Filtr v0.1.2 adds bounded inspection of compressed incoming requests, strict cache-only operation, and broader AI research sources. No UI is required.

### Changes since v0.1.1

- **Compressed request inspection:** accept valid Brotli (`br`), gzip and zlib-wrapped `deflate` bodies when policy permits. Inspect decoded content with the existing filters, then forward the original bytes and encoding. Targeted vulnerability rules can reject an encoding before decompression. Wire size, decoded size, decoder memory, concurrency and execution time are bounded; malformed, truncated or trailing data is rejected. Concatenated gzip members share one output limit.
- **Zero-new-AI operation:** `FILTR_AI_CACHE_ONLY=true` prevents provider and leaderboard calls, including background research. Existing valid cached restrictions remain usable without provider keys. Missing or expired reviews are reported as incomplete; this mode does not renew their age.
- **Atomic cached installation:** `POST /v1/sbom?cache_only=true` installs only a completely reviewed cached candidate. Incomplete analysis returns `409` with `installed:false`, preserving the live policy and saved inventory. Global cache-only mode makes every upload use this behavior; `cache_only=false` cannot override it.
- **Retry control:** `FILTR_AI_HTTP_RETRIES=0..2` controls additional HTTP 429/5xx retries per provider request; the default is 2. Set 0 for a tighter request budget. This does not disable separately configured provider fallback.
- **Research sources:** OpenAI and Anthropic instructions now include [cve.now](https://cve.now/) within the existing hosted-search budget, then require primary-advisory cross-checks. No stack upload or direct database client is added. Compatible targeted-review caches preserve their findings, restrictions and original timestamps; legacy broad findings remain advisory-only.
- **Terminal demo:** a two-tab presentation and read-only baseline checker, plus a guarded inventory-policy replay using genuine cached rules. The replay leaves the running application patched and does not claim to perform an exploit or software deployment. See the [demo guide](https://github.com/meiroio/filtr/blob/v0.1.2/demo/README.md).

### Docker and Kubernetes

`ghcr.io/meiroio/filtr:0.1.2` supports **linux/amd64 and linux/arm64**. Tags include `v0.1.2`, `latest`, `0.1.2-amd64` and `0.1.2-arm64`; prefer a versioned tag or manifest digest for deployments.

```sh
docker pull ghcr.io/meiroio/filtr:0.1.2
curl --fail --location \
  https://github.com/meiroio/filtr/releases/download/v0.1.2/filtr-v0.1.2-kubernetes.yaml \
  --output filtr.yaml
```

Set `FILTR_UPSTREAM`, review namespace/storage settings, and create the private admin Secret before applying the manifest or changing ingress routing. Preserve `/data` across upgrades. Follow the [Kubernetes guide](https://github.com/meiroio/filtr/blob/v0.1.2/docs/kubernetes.md); no local image build is required.

### Simple-mode downloads

| Architecture | Package | Verification |
| --- | --- | --- |
| amd64 / x86_64 | [Linux archive](https://github.com/meiroio/filtr/releases/download/v0.1.2/filtr-v0.1.2-linux-amd64.tar.gz) | [SHA-256](https://github.com/meiroio/filtr/releases/download/v0.1.2/filtr-v0.1.2-linux-amd64.tar.gz.sha256) |
| arm64 / aarch64 | [Linux archive](https://github.com/meiroio/filtr/releases/download/v0.1.2/filtr-v0.1.2-linux-arm64.tar.gz) | [SHA-256](https://github.com/meiroio/filtr/releases/download/v0.1.2/filtr-v0.1.2-linux-arm64.tar.gz.sha256) |

**Each archive includes both profiles:** `apache-php` for Apache with mod_php or a standard PHP-FPM socket, and `node-express` for an unprivileged systemd Node service behind Nginx or Apache. Packages contain the Linux executable, installer, inventory discovery, dry-run/rollback support, reference guides, license and `SHA256SUMS`. Use the [versioned installation commands](https://github.com/meiroio/filtr/blob/v0.1.2/README.md#simple-mode) for supported Debian/Ubuntu hosts.

### Upgrade and validation notes

Keep existing SBOM and cache files. Adding the new research guidance does not require a cache reset; it applies when components next need a permitted review. Outside cache-only mode, `POST /v1/refresh` discards cached reviews and can incur full-inventory charges. Search queries may disclose package identities through the provider's research infrastructure. See [AI behavior and costs](https://github.com/meiroio/filtr/blob/v0.1.2/docs/ai.md).

Before release packaging, **110 Rust tests and Clippy passed**. First-party Rust continues to forbid unsafe code. Performance figures in the README remain the **v0.1.1 benchmark**; this release makes no new performance-measurement claim.

Filtr handles HTTP/1 application traffic; public TLS and HTTP/2/3 termination remain at the ingress. WebSockets, chunked requests, unsupported content encodings and NUL-containing decoded bodies remain unsupported. AI findings are non-exhaustive assessments, and filtering does not replace actual patches. Simple mode supports standard site layouts; custom hosting panels, PM2, containers and complex routing need manual integration.

Licensed under **PolyForm Noncommercial 1.0.0**. See the included LICENSE.
