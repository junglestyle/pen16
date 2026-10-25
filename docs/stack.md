# Tech stack and decisions

Short architecture decision records (ADRs) for pen15's major choices. Each one gives the decision, the alternatives considered, and the tradeoff accepted. New decisions get appended. A reversed decision is marked superseded, not deleted.

## Stack at a glance

| Layer | Choice |
| --- | --- |
| Language | Python 3.12 initially; supported minors explicitly tested |
| API | FastAPI |
| Store | PostgreSQL 16, Alembic migrations |
| Job queue | Postgres (`SKIP LOCKED`) |
| Packaging | Docker images, docker compose |
| Discovery / ports | nmap |
| Vuln checks | nuclei; Greenbone Community Edition as an optional plugin |
| TLS / web | testssl.sh, OWASP ZAP baseline |
| Compliance | OpenSCAP + SCAP Security Guide |
| Probe transport | Tailscale (WireGuard) in the reference deployment |
| LLM interface | Optional provider adapters; local default, hosted explicitly enabled |
| Operator UI | Small server-rendered app alongside FastAPI |
| Dashboards | Grafana optional after the core workflow |
| Secrets | sops + age |
| Deployment | Ansible (`pen15.deploy` collection) |
| Host OS | Debian 13 "trixie" for the scanner VM and probes |
| License | Apache-2.0 |
| Development | uv + lockfile, Ruff, strict mypy, pytest; configured in M0 |

These are design decisions, not installed components. [PLAN.md](PLAN.md) defines delivery order and [CONTRIBUTING.md](CONTRIBUTING.md) defines development/review requirements. Historical decisions below are retained when superseded.

---

## ADR-001: Deterministic scanners, LLM on top

**Decision:** Established scanners do all detection. The LLM triages, explains, writes playbooks and picks follow-up scans from a fixed menu.

**Alternatives:** An autonomous "AI pentester" agent driving tools through a shell.

**Tradeoff:** Less flashy, but results are reproducible, the blast radius is bounded, and the model's job is the part it's actually good at: reasoning over structured history. An agent with a shell on a home network will eventually break something.

## ADR-002: No automated exploitation

**Decision:** pen15 runs safe validation checks only. Anything that would fire a payload becomes a manual playbook with verification tests, and its results come back through the API.

**Alternatives:** Metasploit integration or running public PoCs automatically.

**Tradeoff:** Some findings stay "validated" rather than "exploited" until a human acts. That's acceptable on networks with production or family devices, and it keeps the project clearly defensive.

## ADR-003: PostgreSQL for everything stateful

**Decision:** Postgres holds the model and the job queue.

**Alternatives:** SQLite (simpler, but weak concurrent writes and a harder upgrade path); Redis + Celery for queueing.

**Tradeoff:** One more container than SQLite, but one database to back up, and queue throughput is far beyond what scan scheduling needs.

## ADR-004: Build a thin orchestrator instead of adopting a platform

**Decision:** Write a small Python orchestrator with its own data model.

**Alternatives:** DefectDojo (strong findings management and importers), reNgine/Faraday (recon platforms).

**Tradeoff:** More code to write, but the data model is designed for diffing and agent retrieval, and the footprint fits a NAS VM. DefectDojo can still be fed through its importers if someone wants its UI.

## ADR-005: Python + FastAPI

**Decision:** Python for the orchestrator, parsers and agent; FastAPI for the HTTP API.

**Alternatives:** Go (single binary, fast) or TypeScript.

**Tradeoff:** Go would make a tidier probe binary, but Python has the best parsing libraries for scanner output (python-libnmap, XCCDF/ARF tooling) and the best LLM SDKs, and plugin authors in security mostly write Python.

## ADR-006: One container image per tool

**Decision:** Each scanner runs in its own pinned image, launched per job with minimal capabilities.

**Alternatives:** One fat image with every tool installed.

**Tradeoff:** More images to maintain, but tools upgrade independently, privileges are per tool, and each tool's license stays with its own image (nmap's NPSL, Greenbone's AGPL) rather than being bundled into pen15's.

## ADR-007: Remote probes pull signed jobs over a private tunnel

**Decision:** External scans run on remote probes that connect out to the orchestrator over Tailscale, pull signed jobs and re-check scope locally.

**Alternatives:** Exposing the orchestrator's API publicly; SSH-driven remote execution.

**Tradeoff:** It depends on a tunnel, but the orchestrator never listens on the internet and a compromised probe can't reach the LAN or forge jobs. The transport is pluggable, so plain WireGuard works too.

## ADR-008: LLM backend behind an OpenAI-compatible interface

**Status:** Hosted-fallback defaults and delivery timing superseded by ADR-021. The provider abstraction remains.

**Decision:** The agent talks to any OpenAI-compatible endpoint. The reference deployment uses Ollama on a GPU workstation over the tailnet, with a hosted Claude model as fallback.

**Alternatives:** Hard-coding one provider; running the model on the NAS CPU.

**Tradeoff:** You lose some provider-specific features, but deployers can choose local-only for privacy or hosted for quality. Agent runs are nightly batches, so a fallback when the GPU box is off is enough. A strict-privacy mode waits for the local backend instead of falling back; a pseudonymizer for hosted calls is deferred to phase 5.

## ADR-009: Threat intel from structured feeds first, news second

**Decision:** CISA KEV, NVD and EPSS drive matching. News RSS goes to the human digest only and never triggers a scan. GitHub Security Advisories wait for the code-review product, where they matter.

**Alternatives:** News-driven scanning; LLM fuzzy matching of headlines to assets as a scan trigger.

**Tradeoff:** Zero-days without a CVE reach you as digest items rather than checks, but scans are only triggered by data precise enough to act on, and checks use signed nuclei templates, never PoC code.

## ADR-010: Separate core and deployment repos; sops + age for secrets

**Decision:** The core repo is generic and public; each deployment is its own repo pinning a released image. Secrets are committed only encrypted with sops + age, and the key lives on the host and in a password manager.

**Alternatives:** One repo with gitignored config; git submodules; plaintext secrets in a private repo.

**Tradeoff:** Two repos to manage, but nothing about a specific network ever lands in the public repo, deployments upgrade by bumping a version, and a leaked deployment repo exposes no secrets. An example deployment in the core repo documents the layout.

## ADR-011: Apache-2.0

**Decision:** License the core under Apache-2.0 with a NOTICE file.

**Alternatives:** MIT (shorter, similar permissions); GPL/AGPL (copyleft).

**Tradeoff:** No copyleft protection, but for a project this size copyleft mainly causes rewrites instead of adoption. Apache-2.0 adds an explicit patent grant, and NOTICE carries attribution into derivatives.

## ADR-012: Diff against declared intent, not only the last scan

**Status:** Principle retained; the operator/Git activation workflow is specified by ADR-020.

**Decision:** The deployment declares expected exposure per host and per vantage. Any observed service not declared becomes an "unexpected exposure" finding, and accepting it means adding it to the declaration.

**Alternatives:** Diffing only against the previous scan; relying on vulnerability scanners to flag exposure.

**Tradeoff:** The operator has to write and maintain the declaration. Without it, a service exposed since the first scan never alerts, and a fully patched service reachable from the internet isn't a vulnerability to any scanner.

## ADR-013: A lean core: no masscan, OpenVAS optional, no vector store

**Decision:** nmap is the only port scanner. Greenbone/OpenVAS is an optional plugin. Operator decisions are applied by deterministic suppression rules plus recent decisions in the prompt, with no vector database.

**Alternatives:** masscan for speed; OpenVAS as a core dependency; pgvector retrieval of past decisions.

**Tradeoff:** At home-network scale, nmap is fast enough, and masscan's dropped packets cause false negatives. OpenVAS is the heaviest component (multi-GB feeds, 4–8 GB RAM) and overlaps nuclei heavily; it earns its place for authenticated scanning, not as a baseline. One operator produces dozens of decisions, not millions, so retrieval infrastructure is premature. Each can be added back as a plugin.

## ADR-014: Silence is a failure

**Decision:** Every schedule has a dead-man switch, probes send heartbeats, and a missing run or heartbeat alerts at its own severity.

**Alternatives:** Treating an empty diff as "no change".

**Tradeoff:** More alerts to tune. But a monitoring system that goes quiet when it breaks is worse than none, because quiet reads as safe.

## ADR-015: Scan output is untrusted input to the LLM

**Decision:** Scan-derived text reaches the model only as quoted data with provenance. The agent's outputs are recommendations; it can't close, suppress or accept findings, or lower severity below a deterministic floor.

**Alternatives:** Feeding raw tool output to the model; letting the agent auto-close low-risk findings.

**Tradeoff:** The agent can't save the operator clicks by closing things itself. Banners, titles and certificate fields are attacker-controlled, so letting them steer triage outcomes would turn every scanned device into a way to hide findings.

## ADR-016: Ship a lab and fixtures with the core

**Decision:** The repo includes recorded tool output for parser tests and an isolated compose lab of intentionally vulnerable targets. CI runs a full cycle against the lab.

**Alternatives:** Testing against a live network; unit tests on synthetic data only.

**Tradeoff:** The lab images need maintenance and CI gets slower. In return the system is testable end to end without touching a real network, and the lab is a public demo that exposes nothing about any deployment.

## ADR-017: Deploy with Ansible, roles in the core

**Decision:** The core ships an Ansible collection (`pen15.deploy`) with `server`, `probe` and `oscap_agent` roles. Each deployment repo has `site.yml`, inventory and group vars, pins the collection version, and reads secrets through `community.sops`.

**Alternatives:** Shell scripts; compose-only with manual host setup; ansible-vault for secrets; NixOS.

**Tradeoff:** Ansible is another tool to learn. But pen15 touches three kinds of machines (scanner, probe, every host that pushes OpenSCAP results), and the scanned hosts are where manual setup rots fastest. Keeping roles in the core keeps them reusable, and using the sops lookup avoids a second secrets system. Ansible doesn't create the VM itself; that stays a one-time manual step.

## ADR-018: Debian stable for the scanner and probes

**Decision:** The scanner VM and remote probes run Debian 13 ("trixie"). The `server` and `probe` roles target Debian only.

**Alternatives:** Debian 12 ("bookworm"); Ubuntu LTS; running directly on the NAS OS; an immutable container OS (Fedora CoreOS, Flatcar).

**Tradeoff:** Everything pen15 runs is in containers, so the host only needs to be a stable, boring Docker host, and one OS for scanner and probes means one thing to patch and one set of roles to test. Debian 13 is current stable; Debian 12 is oldstable on LTS, so new deployments shouldn't start there. An immutable OS would shrink the host's attack surface further, but it's a less familiar target for Ansible and for people adopting the project.

## ADR-019: A complete homelab workflow before broad integrations

**Decision:** Optimize for one homelab owner and low routine effort. Ship the internal scan-to-verification loop as v0.1, including basic decisions, UI, health, and recovery. Broader network coverage, external scanning, and structured intelligence build toward v1. Compliance, AI, and analytical dashboards are optional later milestones. Use one core Compose file with opt-in profiles and a host-specific override.

**Alternatives:** Deliver every initial phase-1 scanner together; require the full AI/compliance stack for the first useful release; maintain a separate Compose overlay for each development phase.

**Tradeoff:** Initial coverage is narrower and must be disclosed, but the owner can validate actual usefulness, alert quality, and maintenance effort earlier. Record measurements against [product targets](product.md) and gate releases using [PLAN.md](PLAN.md).

## ADR-020: Built-in operator UI and Git-reviewed intent

**Decision:** Serve a small HTML/CSS application alongside FastAPI for the owner workflow. Grafana is optional and read-only. Expected exposure uses stable asset IDs initially; UI actions export patches against an active revision for the owner to review, commit, and deploy. Validate and activate configurations atomically. An intent change resolves a policy violation with its own reason, without claiming a vulnerability was fixed.

**Alternatives:** Grafana plus manual API calls; a separate SPA; application-held Git credentials and automatic commits; inferred acceptance of every baseline service.

**Tradeoff:** There is a small UI to maintain and declaration changes still require a deployment step. The core workflow becomes accessible without raw API calls, configuration stays auditable, and the scanner does not acquire authority over the owner's repository. See [UX.md](UX.md).

## ADR-021: Optional local-first AI with explicit hosted-data policy

**Decision:** Deterministic monitoring, decisions, intelligence matching, and verification work without an LLM. Add AI later through provider adapters with an OpenAI-compatible internal message interface; provider-specific translation belongs in the adapter. Local inference is default. Hosted calls and fallback each require explicit permitted data, destination, and spend limits. Strict-privacy mode forbids hosted fallback.

**Alternatives:** Enable a hosted fallback whenever the local GPU is unavailable; require AI for threat matching; rely on future pseudonymization before defining disclosure rules.

**Tradeoff:** Optional analysis may remain pending and provider configuration needs explicit choices. The owner retains a working monitor and clear data/cost boundaries. Quoted input is complemented by restricted authority and evaluated output; [SECURITY.md](SECURITY.md) defines the controls.

## ADR-022: Explicit coverage and independent outage detection

**Decision:** Store evidence and coverage separately, with per-vantage findings, immutable provenance, bounded fenced job leases, idempotent ingestion, transactional notification outbox, and append-only transitions. Never infer remediation from missing coverage. Offer an independent watchdog outside the scanner host and alert path.

**Alternatives:** Treat successful scanner exit as complete coverage; close findings missing from any subsequent run; send notifications inline; rely only on the scanner's own health monitor.

**Tradeoff:** More domain state and failure tests are needed, and the independent watchdog needs another failure domain. These are core reliability costs for unattended monitoring. [contracts.md](contracts.md) and [operations.md](operations.md) define exact behavior and defaults.

