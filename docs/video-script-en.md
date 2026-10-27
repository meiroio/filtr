# Four-minute Filtr video script

About 330 spoken words. Aim for roughly 95 words per minute, with pauses for the demo and screen changes. Only the narration is spoken; screen directions are production notes.

Before recording, run the [cache-only preflight](../demo/README.md#prepare-the-replay-without-new-ai-calls). It requires two inventory snapshots and a previously cached Bun/Brotli rule; missing evidence stops the demo. Keep credentials and raw reports off screen. This is an inventory policy replay against still-patched Bun 1.4.4, not a software downgrade, exploit or deployment.

For a terminal-only recording, use the [two-tab presentation](../demo/README.md#two-tab-terminal-presentation): `python3 demo/present.py slides` in tab 1 and the explicit `python3 demo/present.py live --vulnerable-sbom ... --patched-sbom ...` command in tab 2. The deck follows these six sections; `N` toggles this narration.

## 0:00–0:55 — Why I built it

**Screen:** Tab 1, slide 1.

**Narration:**

“Last week felt like vulnerability armageddon.

I was patching Node and Bun vulnerabilities in production. We run Kubernetes, so we already have infrastructure and deployment tools. But every new issue still means investigation, updates, and pressure to move quickly.

This wasn't a theoretical security exercise. It was my week.

That's where Filtr started. I wanted something that could help protect the application while we worked on the actual fix.”

## 0:55–1:30 — What Filtr does

**Screen:** Tab 1, slide 2. Hold this route on screen:

```text
HTTPS ingress → Filtr → Application
```

**Narration:**

“Filtr is a Rust reverse proxy between your ingress and application.

You give it an SBOM: an inventory of your dependencies, runtimes, and container images.

AI researches those versions and proposes specific request filters. Filtr validates the proposals and applies supported rules. Findings without a supported filter stay advisory by default.”

## 1:30–2:15 — A short live demo

**Screen:** Tab 2. Follow the six WHAT/WHY/EXPECT steps. Two cache-only uploads surround four harmless public requests, whose expected responses are **200 → 403 → 200 → 200**. Keep the “inventory policy replay” label visible. Allow about 15 seconds for commands and pauses; stop if preflight or a result fails.

**Narration:**

“Here is a replay using two inventories. Betterpipes itself stays patched.

With the vulnerable Bun inventory, ordinary traffic succeeds, while the cached CVE rule blocks incoming Brotli requests.

Now I upload the patched inventory. The identical Brotli request succeeds. Other protections remain active.

In production, deploy the patch first.”

## 2:15–2:50 — From finding to fixing

**Screen:** Switch to tab 1 and press `4`. The replay has left the patched inventory installed. Explain the real deployment workflow: patch software before uploading its verified inventory.

**Narration:**

“A webhook can notify an SRE agent about findings. The agent can inspect the report, prepare upgrades, and preview a candidate inventory using cached knowledge.

That preview leaves live policy unchanged. Missing reviews remain unknown.

Component reviews are cached for a day by default, reducing repeated AI calls while the team works on patches.”

## 2:50–3:35 — Why simple mode exists

**Screen:** Tab 1, slide 5. Highlight simple mode, prebuilt packages, dry run and rollback.

**Narration:**

“We started with Kubernetes, but I realized this could help people who don't have a Kubernetes team.

So I added simple mode for supported Debian and Ubuntu servers: Apache with PHP, or Node behind Nginx or Apache.

It has prebuilt packages, automatic inventory discovery, a dry run, and rollback.

I've published the source on GitHub, with installation instructions for both simple mode and Kubernetes.”

## 3:35–4:00 — Invite people to try it

**Screen:** Tab 1, slide 6. Hold the repository URL on screen briefly.

**Narration:**

“Filtr is still an MVP. It doesn't replace patching, and AI can miss things.

Try it in a test environment first.

The code is on GitHub, free for noncommercial use. I'd love your feedback.”

**Final frame:** `github.com/meiroio/filtr`
