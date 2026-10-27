# Inventory and SBOM generation

[Back to deployment choices](../README.md)

## SBOM input

Prefer [CycloneDX JSON](https://cyclonedx.org/capabilities/sbom/), with a Package URL (`purl`) for each component. Filtr extracts components from CycloneDX 1.4–1.7, including nested components and `metadata.component`. It also extracts SPDX 2.2/2.3 JSON packages and their `purl` external references. This is an inventory parser, not full SBOM schema validation. SPDX 3 is not supported.

Examples: [`examples/sbom.cdx.json`](https://github.com/meiroio/filtr/blob/v0.1.2/examples/sbom.cdx.json), [`examples/sbom.spdx.json`](https://github.com/meiroio/filtr/blob/v0.1.2/examples/sbom.spdx.json), [`examples/sbom.simple.json`](https://github.com/meiroio/filtr/blob/v0.1.2/examples/sbom.simple.json).

For a hand-written inventory, use this small Filtr-specific format:

```json
{
  "format": "filtr-1",
  "packages": [
    {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
    {"purl": "pkg:npm/react-server-dom-webpack", "version": "19.1.0"}
  ]
}
```

Package identity is matched exactly after PURL normalization. Subpaths and non-Linux qualifiers are ignored; Linux package qualifiers are retained as evidence for AI research. A separate version must agree with the PURL version after supported normalization. Include transitive dependencies and embedded packages: a top-level `next` or `react` entry alone does not identify the RSC packages in the bundled catalogue. Names without PURLs remain visible in coverage but never guess-match a package. Missing, unparseable and prerelease versions enable every curated rule for that package conservatively. Numeric versions with one or two segments are padded with zeros; other non-semver versions are treated as unknown for curated range matching.

Uploads are limited to 64 MiB and 50,000 package components. CycloneDX file artifacts are retained in the uploaded document but excluded from package analysis; nested package components are still inspected. Linux distribution/source qualifiers and RPM epochs are preserved, and Go standard-library display versions such as `go1.26.2` are normalized to their matching PURL versions. Empty inventories are rejected. A package being outside the catalogued version ranges means only that those particular rules did not match; it is not a clean security scan.

## Ask an agent to generate an SBOM

Generate the inventory from the exact deployed release: the final container image or build output, backed by its lockfiles. A manifest containing dependency ranges is insufficient. Include installed transitive dependencies, runtime/framework libraries and embedded packages. Prefer an existing build pipeline's SBOM generator, or a scanner such as [Syft](https://github.com/anchore/syft). Filtr accepts the resulting CycloneDX JSON file directly.

Give your coding/build agent this prompt, replacing the artifact and release identifiers:

```text
Create an SBOM for the application deployed from <image digest or release artifact>.
Inspect the final artifact, dependency lockfiles and existing build/SBOM tooling.
Use a real dependency scanner or the project's existing generator; do not infer
installed versions from dependency ranges or invent package URLs.

For containers, inspect Dockerfiles, build arguments, selected final stages,
platforms and the deployed Compose/Kubernetes image references. Record the actual
running image ID/digest. Verify the final filesystem's /etc/os-release against the
Dockerfile's final base image; a floating FROM tag or a builder-stage OS alone is
insufficient evidence. Preserve the distro ID/version and available CPE metadata
on a CycloneDX operating-system component. Scan installed OS packages too,
retaining their real package PURLs, distro/architecture qualifiers and epochs.
For scratch/distroless or missing os-release, report the available evidence and
limits explicitly; do not guess the OS or silently drop its installed packages.

Write sbom.cdx.json as CycloneDX JSON 1.6 or 1.7. Include every deployed direct,
transitive and embedded component with its name, exact installed version and
Package URL (purl) whenever the source establishes it. Preserve distinct versions
of the same package. Keep unknown identities/versions explicit and list them.

Resolve UNKNOWN/(devel) binary versions before handing over the inventory when
build evidence allows it. For Go, inspect go version -m, upstream build flags,
the exact source release/commit and runtime version output. Preserve embedded
release/VCS metadata during rebuilds. Check replaced/local modules individually:
a helper or submodule does not inherit the main product's release version.
Record the evidence for every enrichment. If a release cannot be established,
retain its verified commit and the unresolved version; do not fabricate a release.

Put image/source attribution in the uploaded SBOM: repeat the component property
filtr:inventory:source for every source and include the JSON-encoded image mapping
in metadata property filtr:inventory:provenance (name, image, image_id). Keep the
full build/version/OS evidence in sbom.sources.json; a sidecar alone cannot give
Filtr source-image attribution. Preserve component types when merging inventories.

Validate the JSON and CycloneDX schema. Also write sbom.sources.json recording
the release/image digest, source commit, scanner command/version, collection time,
component counts and unresolved inventory gaps. Keep this provenance report
separate from the SBOM uploaded to Filtr. Separate known OS records without PURLs
from unknown package versions in the gap report. Return the files, gap report and
generation command. Never invent an OS PURL merely to silence a diagnostic.
```

Regenerate after every deployment that changes dependencies, including rebuilt images and framework patches. Use the release artifact's inventory even when a developer's checkout has newer lockfiles.

For a Docker environment, collect the final application image and every installed third-party service image, including databases, identity providers, ingress and monitoring. Scan their OS packages and embedded libraries. Record the exact local image ID and repository digest for each service. Keep source lockfiles as an additional inventory with their own provenance.

For each image, an offline [Syft image scan](https://oss.anchore.com/docs/guides/sbom/) can use a Docker archive:

```sh
IMAGE=your-application:release
docker image inspect --format '{{.Id}} {{json .RepoDigests}}' "$IMAGE"
docker image save --output image.tar "$IMAGE"
docker run --rm --network none --read-only --tmpfs /tmp \
  --mount "type=bind,src=$PWD/image.tar,dst=/input/image.tar,readonly" \
  -e SYFT_CHECK_FOR_APP_UPDATE=false anchore/syft:v1.46.0 \
  scan docker-archive:/input/image.tar -o cyclonedx-json@1.6 > image.sbom.cdx.json
```

Repeat for each service and merge the results using the next section. Preserve Linux `distro`, `upstream`, architecture and epoch qualifiers when merging. Include standalone runtimes that the scanner did not recognize using version evidence from the image, and record that evidence. Keep unresolved identities explicit. Record which optional service profiles are installed in the target environment.

## Combine inventories from multiple systems with AI

Filtr currently has **one replacement SBOM and one upstream per instance**. Uploading system B's inventory after system A's replaces A; it does not append to it. For a gateway protecting several services, collect one authoritative SBOM per deployed service, worker or embedded runtime reachable through that gateway, then upload their combined inventory. For independent upstreams, deploy separate Filtr instances and send each its relevant inventory. You can also produce a company-wide combined report for reporting, but using that union as a policy makes every finding apply to the entire protected upstream.

Ask an agent to combine the scanner-produced files using deterministic parsing and merging, with AI coordinating the work and explaining gaps. Avoid asking it to summarize the dependency list from memory. A suitable prompt is:

```text
Combine these deployed-system SBOMs: <list of files and system/release identifiers>.
Write combined.sbom.cdx.json as CycloneDX JSON 1.6 or 1.7 for Filtr.

Parse every input with code. Form the union of installed components. Deduplicate
only identical normalized package identity AND exact version; retain all different
versions, even when the package name is the same. Never upgrade, guess, omit or
silently resolve an unknown component/version. Give bom-ref values unique IDs and
retain component types, OS release/CPE metadata and every originating image using
filtr:inventory:source and filtr:inventory:provenance in the uploaded document.
Keep detailed build evidence in a sidecar as well. A known distro without an OS
PURL and a binary with an unknown version are different issues; report both clearly.

Write combined.sources.json with the input filenames, deployment/image digests,
input/output component counts, duplicate decisions and unresolved gaps. Produce
and run a script that compares every input package/version with the output and
fails on any omission. Validate the output schema. Check Filtr's 64 MiB / 50,000
component limits; if exceeded, report it and propose splitting by protected upstream.
Return the merged file, provenance report and reproducible merge/check script.
```

Review the merge's count/provenance report against all input files before deploying it. Keep both, for example, `pkg:pypi/jinja2@3.1.2` and `pkg:pypi/jinja2@3.1.6` if different services run those versions. Filtr cannot associate a dependency with a particular HTTP route: combining services can therefore broaden matching request restrictions; manual or opted-in emergency blocking affects the entire gateway. Missing identities and versions remain visible as inventory gaps without automatic quarantine. Split unrelated systems into separate policies rather than dropping components to fit limits.

Upload the result using the [API guide](api.md#send-an-sbom-to-a-running-filtr-instance).
