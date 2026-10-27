# Simple-mode reference

[Back to deployment choices](../README.md)

## Apache and PHP

Simple mode installs a prebuilt Linux binary, discovers the real inventory, uploads an SBOM and configures one Apache website. No Rust toolchain or UI is required. The [release workflow](https://github.com/meiroio/filtr/blob/v0.1.1/.github/workflows/release.yml) produces **amd64 and arm64** archives. Manual runs create build artifacts; version-tag builds publish archives and checksums on [GitHub Releases](https://github.com/meiroio/filtr/releases).

Supported hosts are **Debian 12+ or Ubuntu 22.04+**, with distribution Apache2 packages, Python 3, systemd and CA certificates. The profile accepts one application virtual host on port 80 or 443, plus an optional simple HTTP-to-HTTPS redirect for that hostname. PHP can use enabled mod_php or a standard `/run/php/phpVERSION-fpm.sock` handler. Apache retains certificate ownership and renewal paths. Other sites remain outside this installation's protection.

Use the [versioned download and checksum commands](../README.md#download) before running this profile.

The archive includes a standalone musl Linux binary, installer sources, license, README and checksums. The installer verifies the adjacent binary before execution. A separately built local executable needs `--binary /absolute/path/filtr --binary-sha256 EXPECTED_HASH`. Checksums detect changes; obtain them from a trusted release channel.

The flow is **public Apache/TLS → Filtr on 127.0.0.1:8080 → private Apache/PHP on 127.0.0.1:8081**. Administration uses loopback port 9090. The public host overwrites forwarding headers. Filtr trusts only that local peer, applies the site's hostname allowlist and preserves canonical host/client/scheme/port metadata. The backend applies trusted HTTPS metadata for PHP and the client address for Apache. Apache's public HTTP/TLS parsers still run before Filtr and need their own security updates. Local processes can reach loopback listeners; this profile does not isolate mutually untrusted tenants.

**Dry-run does not install files, save an SBOM/cache, download binaries, start/reload services or call AI.** It reads metadata and runs Apache configuration checks, reporting the detected site/runtime, inventory count, gaps, routing and affected Apache paths. Apply checks the current website, saves a root-only rollback journal, installs a dedicated unprivileged `filtr-simple` systemd service, checks the new configuration, uploads the inventory and probes the public website. The request counter must confirm that the probe traversed Filtr. An operator/opt-in emergency block is retained and reported as a deliberate 403, rather than undoing protection because the website is blocked. Use `--health-path /working-path` when `/` is not a healthy public route. HTTPS probes keep SNI and certificate validation; `--ca-file /path/to/private-ca.pem` supports private CAs.

The bounded profile refuses wildcard names, shared multi-site files, extra application virtual hosts, site-level proxy/rewrite rules, arbitrary site includes, symlinked application directories, client-certificate authorization and HTTPS/SERVER_PORT redirects in `.htaccess` requiring adaptation. Hosting panels, containers, custom Apache/PHP layouts and shared tenancy need reviewed manual integration. Existing Filtr binaries/configuration or policy data are not overwritten. `--listen-port`, `--backend-port` and `--admin-port` select free, distinct unprivileged ports.

Discovery includes installed `dpkg` packages with exact vendor versions, epochs, architecture, source build and distribution qualifiers. PHP evidence comes from enabled Apache handlers, rather than the CLI PHP version. Unmanaged runtime files become gaps. Application discovery reads Composer's **installed** package metadata and recognizable WordPress core/plugin/theme headers, without executing PHP, Composer plugins or project scripts. Missing versions, development branches, unidentified custom code and bundled libraries remain explicit gaps. WordPress headers do not inventory every bundled library; merge additional artifact scans when needed. Containers, other sites and external services require their own inventories.

To save a CycloneDX 1.6 inventory without installing:

```sh
sudo ./filtr-install --site example.com --discover-only /root/site-sbom.json
```

AI credentials are optional. Without keys, targeted static filtering is active and AI coverage remains unknown. To enable AI, create `/root/filtr-ai.env` with mode `600`, for example:

```dotenv
ANTHROPIC_API_KEY=replace-with-your-key
FILTR_AI_PROVIDER=anthropic
# Optional exact provider model instead of the leaderboard winner:
# FILTR_AI_MODEL=your-chosen-model-id
FILTR_AI_CACHE_TTL_SECS=86400
# OPENAI_API_KEY enables the configured Luna backup.
```

Pass `--env-file /root/filtr-ai.env` to dry-run/apply. The file is parsed as data, never sourced as shell. It accepts documented AI/model/cache/deadline settings, webhook settings, `FILTR_AUTO_BLOCK_CRITICAL` and the three HTTP resource limits; it cannot override routing/admin credentials. Settings are saved privately in `/etc/filtr/filtr.env`, with a newly generated 64-byte admin secret. Secrets never enter subprocess arguments or plan output. AI-enabled uploads may incur charges for cache misses; provider failure retains targeted static filtering.

Simple mode uses an **8 MiB body limit, 64 concurrent requests and a 30-second timeout**. Override with `FILTR_MAX_BODY_BYTES`, `FILTR_MAX_IN_FLIGHT` and `FILTR_TIMEOUT_SECS` in the optional file; the supported body maximum remains 16 MiB. Size memory for buffered bodies and test uploads. Text multipart uploads are supported; binary content containing NUL bytes and streaming/chunked requests remain unsupported. Published v0.1.1 packages reject compressed uploads; source builds after v0.1.1 inspect Brotli, gzip and zlib-wrapped deflate under the [HTTP resource bounds](operations.md#http-behavior). Test these application flows before rollout.

After dependency or application upgrades:

```sh
sudo filtr-simple --refresh-inventory
```

Unchanged inventory skips the upload and requests no AI work. Changed inventory is uploaded and reuses unexpired component reviews; misses/expired entries can require AI calls. It does not clear the cache. Filtr's existing TTL scheduler refreshes vulnerability recommendations between inventory updates. Integrate rediscovery into deployment/package maintenance; there is no automatic package upgrade. The upload result, including readable gaps and AI status, is saved privately at `/var/lib/filtr-simple/last-upload.json`. Existing admin APIs and agent instructions apply.

Apply automatically attempts rollback after configuration, service, upload or website-check failure. Explicit recovery is:

```sh
sudo filtr-simple --rollback
# If an interrupted install did not leave that command:
sudo ./filtr-install --rollback
```

`/var/lib/filtr-simple/transaction.json` and private backups record original bytes, owner/mode, symlinks and absent paths. Rollback restores/checks/reloads the original Apache routing before stopping Filtr. Later operator edits to managed files cause explicit rollback to refuse overwriting them; reconcile those changes first. Interrupted operations retain the journal. Failed automatic recovery reports its journal path. SBOM/cache/report data and the service account are retained for investigation; archive the data before a fresh installation. Reload/rollback can briefly interrupt service; this installer does not promise zero downtime.


## Simple mode: Node / Express

The same prebuilt archives also include `--profile node-express` for **Debian 12+ / Ubuntu 22.04+**, with an existing unprivileged Node systemd service behind Nginx or Apache. The installer inspects the live runtime and installed dependency tree, uploads the generated SBOM and changes the frontend to route through Filtr. The Node service, application code and dependencies are left unchanged.

For a standard Nginx site:

```sh
sudo ./filtr-install --profile node-express \
  --site api.example.com --app-service my-api.service --dry-run

sudo ./filtr-install --profile node-express \
  --site api.example.com --app-service my-api.service \
  --env-file /root/filtr-ai.env
```

`--env-file` is optional; without AI keys, targeted static filtering remains active and AI vulnerability coverage is unknown. Model override, cache lifetime, SRE webhook, private admin credentials, traffic modes and rollback behave as in the Apache/PHP profile. Dry-run makes no AI requests or installation changes. Node discovery requires sudo to inspect the selected process safely.

The app root defaults to the service's explicit `WorkingDirectory`. Set `--app-dir /srv/my-api` for a workspace/monorepo root containing that working directory. The backend port is discovered from sockets owned by the service's **MainPID**; use `--backend-port 3000` when it has multiple listeners. MainPID must be Node itself under an unprivileged UID/group. Shell launchers, PM2 managers, containers and services without an explicit working directory need manual integration. The selected HTTP listener must already bind only to `127.0.0.1` or `::1`; a public/wildcard origin is rejected so clients cannot bypass Filtr. The installer does not guess whether an application's code honors `HOST`/`PORT` variables or alter firewall rules.

The route becomes:

```text
Existing Nginx/Apache HTTPS frontend
  -> Filtr, 127.0.0.1:8080
  -> existing private Express listener, for example 127.0.0.1:3000
```

Nginx is the default frontend. Its supported layout has explicit `server_name` values, a single `location /` with a fixed `proxy_pass` to the selected loopback port, and optionally an HTTP-to-HTTPS redirect. Certificates and applicable custom headers are preserved. Root proxy headers are rebuilt to overwrite client-supplied forwarding metadata, while request buffering is enabled and proxy caching/error interception is disabled so requests and block responses traverse Filtr. Split/regex locations, dynamic/named upstreams, arbitrary includes and WebSocket upgrade configurations require manual integration. The standard Let's Encrypt TLS-options include is accepted after checking that it contains only TLS directives.

For an existing Apache reverse-proxy site, add `--web-server apache`. That profile requires matching root `ProxyPass` / `ProxyPassReverse` directives targeting the selected private Node port. It reuses the existing public TLS virtual host without creating a PHP/backend Apache virtual host. Both frontends retain certificate files; their own HTTP/TLS parser vulnerabilities remain outside Filtr's inspection path.

Express must use a proxy-trust setting appropriate to this private chain to derive `req.protocol`, `req.secure`, `req.hostname` and `req.ip`. For a conventional host-local deployment, application configuration can use:

```js
app.set('trust proxy', 'loopback');
app.listen(3000, '127.0.0.1');
```

This is application configuration guidance, not a source-code edit performed by the installer. Do not use an unrestricted `trust proxy: true` setting without matching the entire deployment's trust boundary. See [Express's proxy guidance](https://expressjs.com/en/guide/behind-proxies/). Verify redirects, secure cookies and authentication through the public frontend; successful status probes alone cannot prove every application-level trust setting.

Node discovery reads installed `node_modules/**/package.json` files, including nested versions, scoped packages, workspace links inside the selected app root and standard pnpm stores. npm/Yarn layouts using node_modules are supported. Lockfiles and dependency ranges alone never become claims about installed versions. Yarn PnP, bundled applications, external workspace symlinks, missing exact versions and private package identities require a verified artifact SBOM; gaps remain explicit. No npm install/audit command, lifecycle script, package code or project executable is run by discovery.

The runtime is the selected process's executable, not whichever `node` appears on root's PATH. A fixed built-in `process.versions` expression runs as the app UID without project imports or inherited Node startup options; output/time are bounded. The actual Node version and embedded-library version evidence are recorded. Matching distribution-managed runtimes retain the distro package identity/build so backports are not replaced by a guessed upstream version. Unpackaged or replaced runtimes retain the observed upstream version plus a build-provenance gap. Native-addon internals, bundled/vendor patches, custom code and external services still need additional build/image inventories.

Installed-profile maintenance uses the same commands and private reports. Complete the application's release/restart procedure after dependency changes before refreshing: installed files describe the deployed tree, while a running Node process can retain older modules in memory.

```sh
sudo filtr-simple --refresh-inventory
sudo filtr-simple --rollback
```

Unchanged inventory skips upload and requests no AI work. Changed versions reuse valid component reviews; misses/expired reviews can incur charges. Rediscovery follows the saved Node profile and checks the current live service. Rollback restores the original frontend configuration before stopping Filtr, without restarting or changing the Node app. Existing HTTP/body limits still apply, including restrictions on WebSockets, streaming/chunked bodies and NUL-containing binary uploads.
