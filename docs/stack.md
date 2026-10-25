# Stack and decisions

These are planned choices. [PLAN.md](PLAN.md) is the delivery authority. ADR-029 replaces the earlier broad roadmap and controls the current design where older decisions differ. Earlier records are summarized below for traceability; their former milestone numbers and feature promises are retired.

## Current stack

| Layer | Choice and reason |
| --- | --- |
| Core | Python 3.12 + FastAPI; one service with typed internal modules |
| Dashboard | Server-rendered HTML/CSS with progressive enhancement; same services/API as integrations |
| State | PostgreSQL 16 + Alembic; inventory, settings, simple job claims, history, and outbox in one store |
| Evidence | Immutable compressed files; bounded retention and encrypted backup |
| Scanner | Pinned nmap image in one serial pull runner with `NET_RAW` |
| Deployment | Docker Compose and Ansible on existing Debian 13 hosts |
| Network boundary | Host-managed nftables netdev egress; private owner and separate runner listeners |
| Remote transport | Tailscale in the reference deployment; one external probe |
| Private TLS | Caddy with the Tailscale certificate integration in the reference deployment |
| Secrets | sops + age, controller-side decryption, restricted runtime files |
| Intelligence | KEV and selected advisory feeds; optional NVD enrichment |
| Notifications | ntfy-compatible HTTP POST; optional digest and external-monitor ping |
| Development | uv, Ruff, mypy, pytest, isolated listener lab |
| License | Apache-2.0 for the core; tool redistribution reviewed separately |

## ADR-029: A small, tunable monitor that demonstrates infrastructure judgment

**Decision:** Build a useful dashboard and a bounded API for one homelab owner. The product should run unattended and support gradual tuning. Demonstrate capability through reproducible deployment, explicit trust boundaries, secret handling, failure tests, and restore evidence. Compliance breadth and absolute assurance are not success measures.

**Delivery:** M1 delivers internal observation, dashboard, API, and recovery. M2 adds lightweight vulnerability awareness; M3 adds one external vantage. Both complete v1. A configured assistant such as Hermes can read permitted data and request approved scans through the same API. No built-in model is needed.

**Simplifications:** Findings are open/resolved with separate decisions and labeled evidence. Assets, exposure, and settings live in the database with optional atomic export/import. Use serial runners and authenticated TLS assignments, with deadlines and stale-attempt rejection but no separate signing or machine-rotation service. Tokens are scoped/revocable with optional expiry. Accepted-risk review dates are optional. A repeated-filtering heuristic is allowed with honest labeling and an owner override.

**Cuts:** Remove deployment announcements, population-drop heuristics, compulsory decision/token renewals, automatic closure from client ageing, generic result ingest, a public plugin API, a remediation-planning workflow, and committed compliance/AI/reporting milestones. No risk score, Grafana dependency, mandatory weekly review, or ongoing Git synchronization. Broad discovery/check integrations are future use cases, not scaffolding requirements.

**Future remediation:** API-triggered remediation may later expose a few named owner-approved actions with explicit plans, separate permission, bounded execution, and verification/rollback. Monitoring credentials never acquire this authority automatically. Arbitrary shell execution and autonomous remediation remain out of scope.

**Alternatives:** Continue implementing every prior FR and milestone; build a compliance/scanner platform; limit the project to raw scanner output without a dashboard or API.

**Tradeoff:** Less assessment breadth and fewer guarantees. Inventory, feeds, and one vantage can miss things; filtered observations are heuristic. These limits are acceptable when visible. The project earns confidence by catching realistic problems, staying within scope, and recovering reliably while demanding little owner attention.

## Earlier decision ledger

This ledger preserves the decisions and why they mattered without leaving obsolete behavior as a second specification. Current behavior is fully defined by ADR-029 and the linked normative documents.

| ADR | Disposition under ADR-029 |
| --- | --- |
| 001 — Deterministic scanners, LLM on top | Deterministic monitoring retained; built-in AI and follow-up selection removed from committed scope. A restricted external assistant can use the API. |
| 002 — No automated exploitation | Retained. Future approved remediation is distinct from exploit validation. |
| 003 — Postgres for state and queue | Retained to avoid a separate queue service; execution is serial per runner. |
| 004 — Thin orchestrator | Retained for the exposure/history workflow; no general security platform. |
| 005 — Python + FastAPI | Retained for scanner integration and a small dashboard/API. |
| 006 — Per-tool pinned images | Pinned images retained; per-job container launching superseded by 024 and 029. |
| 007 — Pull signed jobs over a private tunnel | Pull/private transport retained; application signatures superseded by authenticated TLS assignments, local expiry, and resource binding in 029. |
| 008 — OpenAI-compatible backend | Removed from committed scope; external assistants need only the API. |
| 009 — Structured intelligence before news-driven scans | Relevant structured matching retained; advisories without CVEs can surface for review, and v1 intelligence never starts scans. |
| 010 — Separate core/deployment and sops/age | Retained; controller key custody governed by 026. Database-held settings need no recurring Git synchronization. |
| 011 — Apache-2.0 | Retained. |
| 012 — Diff against intent | Retained; bulk database declarations governed by 029. |
| 013 — Lean scanner core | nmap retained; OpenVAS and a vector store have no committed role. |
| 014 — Silence is a failure | Operational health retained; sleeping clients are not failed execution. |
| 015 — Scan output is untrusted | Retained for parsers, UI, and assistant-facing API; no model-specific machinery is required. |
| 016 — Lab and fixtures | Retained with small listeners/filtering first, not a vulnerable application fleet. |
| 017 — Ansible roles in core | Server/probe roles retained; OpenSCAP agent role removed. |
| 018 — Debian stable reference hosts | Debian 13 retained to constrain deployment/testing scope. |
| 019 — Complete homelab loop first | Retained in M1; later scope replaced by 029. |
| 020 — Built-in UI and Git-reviewed intent | Dashboard retained; Git activation superseded by 023 and 029. |
| 021 — Optional local-first AI | Hosted-data caution retained; built-in inference removed from committed scope. |
| 022 — Coverage and independent outage detection | Evidence/outbox/recovery retained; the owner supplies an optional external monitor. |
| 023 — App-held intent and announcements | App-held intent retained with atomic bundle export; announcements removed. |
| 024 — Long-lived pull runner | Retained; host deployment owns firewall lifecycle and serial execution under 029. |
| 025 — Declared coverage denominator | Target/port manifests and reachability witness retained; population heuristic removed and weekly sweep becomes a visible freshness goal. |
| 026 — Controller-side decryption | Retained to keep the deployment decryption key off the scanner host. |
| 027 — Internal interfaces before plugins | Internal interfaces retained; two implementations no longer automatically trigger a public API. |
| 028 — v1 is internal plus outside view | Superseded: v1 also includes lightweight vulnerability awareness, without a vulnerability scanner dependency. |
