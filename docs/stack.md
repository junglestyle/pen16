# Stack and decisions

## Current stack

| Layer | Choice |
| --- | --- |
| Core | Python 3.12, FastAPI |
| Dashboard | Server-rendered HTML/CSS, progressive enhancement |
| State | PostgreSQL 16, Alembic |
| Evidence | Immutable compressed files |
| Scanner | Pinned nmap, serial pull runner |
| Deployment | Docker Compose, Ansible, Debian 13 |
| Network boundary | Host-managed nftables netdev egress |
| Remote transport | Tailscale, separate runner listener |
| Private TLS + owner auth | tailscale serve |
| Secrets | sops + age, controller-side decryption |
| Intelligence (M2) | KEV, selected advisories, optional NVD |
| Notifications | ntfy-compatible HTTP POST |
| Development | uv, Ruff, mypy, pytest, isolated listener lab |
| License | Apache-2.0; check tool redistribution terms before publishing images |

## ADR-001: A small, tunable homelab monitor

Build the internal dashboard loop first, then advisory awareness and one external vantage. Run unattended and demonstrate deployment, boundaries, failure handling, and recovery. An external assistant uses the restricted API; core operation needs no model. Keep the pilot small enough to finish and use.

## ADR-002: Postgres for state and jobs

Use one store for settings, evidence metadata, findings, jobs, and notification retries. Serial runners and database transactions avoid a separate queue service.

## ADR-003: Separate deployment and application state

Keep scope, ceilings, networking, and encrypted secrets in a private deployment repository. Keep routine settings and intent in the database so dashboard changes need no deployment or Git synchronization. Controller-side decryption keeps the deployment key off the scanner host.

## ADR-004: Enforce scan scope on the host

Raw-packet scanning needs an egress boundary outside the runner process. Ansible installs policy before execution and keeps firewall authority away from the runner. Prove containment with raw-packet tests in the isolated lab.

## ADR-005: Tailscale identity instead of passwords

The dashboard is only reachable over Tailscale, so it uses Tailscale identity for the owner instead of its own login system. That means no passwords, sessions or recovery flow to build or maintain. API tokens still cover assistant clients and runners.
