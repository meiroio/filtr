Filtr's first packaged release provides an API-only HTTP reverse proxy and simple-mode installers for Debian/Ubuntu hosts.

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
- Kubernetes manifests and Docker build instructions for an operator-supplied image and deployed-environment SBOM.

### Scope

Filtr handles HTTP/1 application requests. Public TLS and HTTP/2/3 termination remain at the ingress. WebSockets, chunked/compressed request bodies, and NUL-containing binary uploads are unsupported. Simple mode supports bounded standard site layouts; custom hosting panels, PM2 managers, containers, and complex routing require manual integration.

AI credentials are optional. Without them, baseline/curated filtering works but AI coverage is unknown. AI-enabled reviews can incur charges. No review guarantees complete vulnerability coverage.

Licensed under PolyForm Noncommercial 1.0.0. See the included LICENSE.
