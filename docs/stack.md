# Stack and decisions

## Current stack

| Layer | Choice |
| --- | --- |
| Core | Python 3.15, FastAPI |
| Dashboard | Server-rendered HTML/CSS, progressive enhancement |
| State | PostgreSQL 16, SQLAlchemy Core, Alembic |
| Evidence | Immutable compressed files |
| Scanner | Pinned nmap, serial pull runner |
| Compliance | OpenSCAP on each host, pinned SCAP Security Guide content, push to an intake |
| Deployment | Docker Compose, Ansible, Debian 13 |
| Network boundary | Host-managed nftables netdev egress |
| Remote transport | Tailscale, separate runner listener |
| Private TLS + owner auth | tailscale serve |
| Secrets | sops + age, controller-side decryption |
| Intelligence (M2) | KEV, selected advisories, optional NVD |
| Notifications | ntfy-compatible HTTP POST |
| Development | uv, Ruff, mypy, pytest, isolated listener lab |
| License | MIT; check tool redistribution terms before publishing images |

## ADR-001: A small, tunable homelab monitor

Build the internal dashboard loop first, then advisory awareness and one external vantage. Run unattended and demonstrate deployment, boundaries, failure handling, and recovery. An external assistant uses the restricted API; core operation needs no model. Keep the pilot small enough to finish and use.

## ADR-002: Postgres for state and jobs

Use one store for settings, evidence metadata, findings, jobs, and notification retries. Serial runners and database transactions avoid a separate queue service.

## ADR-003: Separate deployment and application state

Keep scope, ceilings, networking, and encrypted secrets in a private deployment repository. Keep routine settings and intent in the database so dashboard changes need no deployment or Git synchronization. Controller-side decryption keeps the deployment key off the scanner host.

## ADR-004: Enforce scan scope on the host

Raw-packet scanning needs an egress boundary outside the runner process. The host installs policy before execution and keeps firewall authority away from the runner. Prove containment with raw-packet tests in the isolated lab.

## ADR-005: Tailscale identity instead of passwords

The dashboard is only reachable over Tailscale, so it uses Tailscale identity for the owner instead of its own login system. That means no passwords, sessions or recovery flow to build or maintain. API tokens still cover assistant clients and runners.

## ADR-006: SQLAlchemy Core and Alembic instead of SQL files

The org default is raw SQL through psycopg and numbered `NNN_name.sql` migrations. pen16 declares its tables once, in `db.py`, and builds queries from them with SQLAlchemy Core: no ORM, no sessions, no mapped classes. That one declaration also drives Alembic, so `alembic check` in `make check` fails when the migrations and the tables the code queries drift apart, which plain SQL files can't catch. The locking and dedup the job queue needs (`FOR UPDATE SKIP LOCKED`, `DISTINCT ON`, `RETURNING`) compose as expressions instead of strings. Migrations are numbered Python files, applied once each and never edited after they ship, so the intent of the SQL-file rule carries over; the rule itself doesn't apply here.

## ADR-007: FastAPI and uvicorn for the dashboard and listener

The dashboard, the runner listener, and the versioned API are all HTTP, and each one checks who is calling before it does anything. FastAPI gives the owner check and the runner token check as dependencies every route must pass, validates uploads at the trust edge, parses forms, and produces the OpenAPI schema FR-10 publishes with its permissions. uvicorn serves it and handles SIGTERM. Routes stay synchronous functions; the framework runs them off its event loop, so the rest of the code needs no async. The stdlib's server has none of the validation or form handling, and a sync framework would need a separate validation layer and schema generator.

## ADR-008: OpenSCAP in push mode with pinned SCAP Security Guide content

Host compliance uses OpenSCAP and the ComplianceAsCode SCAP Security Guide: the common open content for automated DISA STIG checks. It carries STIG, SRG, CCI and NIST 800-53 references per rule, so a checklist and a pass rate come out of one result. Each host runs `oscap` itself and pushes the ARF, so pen16 holds no SSH keys or accounts on the hosts it reports on; pulling over SSH would make pen16 the most valuable credential on the network. The content is a pinned upstream release, verified by checksum and bumped like any other pin, because distribution packages lag new releases and vary by host. Tailoring files and custom content live in the deployment repository with the hosts they apply to. Alternatives: Lynis or a CIS-CAT agent report without STIG mapping or a standard result format, and agent platforms such as Wazuh bring a server to run and patch.
