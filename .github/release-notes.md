Filtr v0.1.1 ships the optimized HTTP request path, with the existing targeted filtering and traffic controls.

### Changes since v0.1.0

- Combine NUL/escape detection using safe byte-search APIs from the existing memchr dependency.
- Reuse the validated upstream origin instead of reparsing it for every request.
- Move owned header maps and reuse parsed hop-header names to reduce allocation and copying.
- Add paired baseline/candidate Docker benchmarking and record profiling and regression evidence.

A fresh paired ARM64 Docker benchmark measured 10.4% higher GET throughput, 11.9% for 1 KiB POSTs and 15.9% for 64 KiB POSTs with the optimized source build. These are shared-development-host results with 2-CPU quotas, rather than production capacity guarantees. The pre-release measurements and exact setup are linked from the README. All 81 Rust tests and Clippy passed, and 111 baseline/candidate HTTP cases produced identical responses, including 83 rejections. First-party unsafe Rust remains forbidden.

### Docker and Kubernetes

The public `ghcr.io/meiroio/filtr:0.1.1` tag supports linux/amd64 and linux/arm64. Version aliases `v0.1.1` and `latest`, plus architecture-specific `0.1.1-amd64` and `0.1.1-arm64` tags, are also published.

```sh
docker pull ghcr.io/meiroio/filtr:0.1.1
curl --fail --location \
  https://github.com/meiroio/filtr/releases/download/v0.1.1/filtr-v0.1.1-kubernetes.yaml \
  --output filtr.yaml
```

Edit `FILTR_UPSTREAM` and the cluster namespace/storage settings, create the private admin Secret and follow the [Kubernetes guide](https://github.com/meiroio/filtr/blob/v0.1.1/docs/kubernetes.md) before changing ingress routing. The manifest already selects the published image; no local image build is required.

### Downloads

Choose the `linux-amd64` or `linux-arm64` archive for your server. **Each archive includes both profiles**:

- `apache-php`: Apache with mod_php or a standard PHP-FPM socket.
- `node-express`: an unprivileged systemd Node service behind Nginx or Apache, with a private loopback backend.

The archives include the standalone Linux executable, installer, reference guides, license, and `SHA256SUMS`. A separate `.tar.gz.sha256` file verifies each archive. Follow the versioned download and installation commands in the README.

### Included functionality

- Installed-package and application inventory discovery, readable SBOM gaps, dry-run, and rollback.
- Hostname/HTTPS forwarding with explicit proxy trust.
- Targeted filtering by default; uncovered findings are advisory-only.
- OpenAI/Anthropic vulnerability research, model override, persistent component cache, and automatic expiry refresh.
- Cache-only SBOM previews, remediation reports, maintenance webhooks, and persistent traffic controls.
- Optional source-backed AI critical-risk escalation; full blocking is disabled by default.
- Public GHCR runtime image for linux/amd64 and linux/arm64, plus a Kubernetes manifest and deployed-environment SBOM instructions.

### Scope

Filtr handles HTTP/1 application requests. Public TLS and HTTP/2/3 termination remain at the ingress. WebSockets, chunked/compressed request bodies, and NUL-containing binary uploads are unsupported. Simple mode supports bounded standard site layouts; custom hosting panels, PM2 managers, containers, and complex routing require manual integration.

AI credentials are optional. Without them, baseline/curated filtering works but AI coverage is unknown. AI-enabled reviews can incur charges. No review guarantees complete vulnerability coverage.

Licensed under PolyForm Noncommercial 1.0.0. See the included LICENSE.
