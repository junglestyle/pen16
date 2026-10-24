# Tech stack and decisions

Short architecture decision records (ADRs) for pen15's major choices. Each one gives the decision, the alternatives considered, and the tradeoff accepted. New decisions get appended. A reversed decision is marked superseded, not deleted.

## Stack at a glance

| Layer | Choice |
| --- | --- |
| Language | Python 3.12+ |
| API | FastAPI |
| Store | PostgreSQL 16 + pgvector |
| Job queue | Postgres (`SKIP LOCKED`) |
| Packaging | Docker images, docker compose |
| Discovery / ports | nmap, masscan |
| Vuln checks | nuclei, Greenbone Community Edition |
| TLS / web | testssl.sh, OWASP ZAP baseline |
| Compliance | OpenSCAP + SCAP Security Guide |
| Probe transport | Tailscale (WireGuard) in the reference deployment |
| LLM interface | OpenAI-compatible; Ollama locally, Claude hosted |
| Dashboards | Grafana |
| Secrets | sops + age |
| License | Apache-2.0 |

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

**Decision:** Postgres holds the model, the job queue and embeddings (pgvector).

**Alternatives:** SQLite (simpler, but no pgvector and weak concurrent writes); Redis + Celery for queueing; a separate vector DB.

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

**Decision:** The agent talks to any OpenAI-compatible endpoint. The reference deployment uses Ollama on a GPU workstation over the tailnet, with a hosted Claude model as fallback.

**Alternatives:** Hard-coding one provider; running the model on the NAS CPU.

**Tradeoff:** You lose some provider-specific features, but deployers can choose local-only for privacy or hosted for quality. Agent runs are nightly batches, so a fallback when the GPU box is off is enough. An optional pseudonymizer covers hosted use.

## ADR-009: Threat intel from structured feeds first, news second

**Decision:** CISA KEV, NVD, EPSS and GHSA drive matching; news RSS is supplementary and only matched through flagged fuzzy LLM matching.

**Alternatives:** News-driven scanning.

**Tradeoff:** Zero-days without a CVE show up as "potentially affected" rather than being checked, but scans are only triggered by data precise enough to act on, and checks use signed nuclei templates, never PoC code.

## ADR-010: Separate core and deployment repos; sops + age for secrets

**Decision:** The core repo is generic and public; each deployment is its own repo pinning a released image. Secrets are committed only encrypted with sops + age, and the key lives on the host and in a password manager.

**Alternatives:** One repo with gitignored config; git submodules; plaintext secrets in a private repo.

**Tradeoff:** Two repos to manage, but nothing about a specific network ever lands in the public repo, deployments upgrade by bumping a version, and a leaked deployment repo exposes no secrets. An example deployment in the core repo documents the layout.

## ADR-011: Apache-2.0

**Decision:** License the core under Apache-2.0 with a NOTICE file.

**Alternatives:** MIT (shorter, similar permissions); GPL/AGPL (copyleft).

**Tradeoff:** No copyleft protection, but for a project this size copyleft mainly causes rewrites instead of adoption. Apache-2.0 adds an explicit patent grant, and NOTICE carries attribution into derivatives.
