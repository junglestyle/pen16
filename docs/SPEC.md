# pen15 specification

This is a planned personal attack-surface monitor, not shipped software. [product.md](product.md) defines purpose and success; [PLAN.md](PLAN.md) defines delivery. The dashboard and restricted API are core. Lightweight vulnerability awareness and one external vantage complete v1.

## Scope

Monitor the owner's authorized infrastructure, compare exposure with intent, surface relevant emerging disclosures, and make operational failures visible. Setup should lead to unattended operation with optional dashboard use and incremental tuning. Core operation needs no LLM or paid service.

No enterprise tenancy, certification claim, intrusion prevention, exploitation, generic scanner platform, or autonomous remediation is included. Future approved API remediation has its own design gate in [PLAN.md](PLAN.md).

## Functional requirements

Existing IDs are retained for traceability; retired IDs below are not requirements to implement.

### Scope, discovery, and exposure

- **FR-1** Resolve and validate targets against explicit scope before dispatch; enforce network scope outside the runner process.
- **FR-2** External jobs for dynamic public targets compare DDNS with deployment-observed addresses for each enabled family. Mismatch skips work and degrades health.
- **FR-3** `exclude` prohibits probes to the host; `fragile` permits only an explicit light port set at a lower rate. Ordinary link-layer broadcasts on a shared segment are not a guarantee of zero received frames.
- **FR-4** Record who requested a job and why.
- **FR-5** Compare observed services with owner-declared exposure per asset/protocol/port/vantage on every run. Support bulk declarations in the dashboard, history, and explicit export/import. New observations never implicitly become expected.
- **FR-7** Declare each network's discovery method: an L2 interface, or a bounded routed address/host list scanned without relying on ping discovery. Check a configured reachability witness per network; expose the limits of that check.
- **FR-8** Use stable owner-chosen IDs for declared assets and explicit bindings. Infer unknown identities conservatively; do not transfer decisions on IP reuse. Support owner retirement, retaining history.
- **FR-9** Start with nightly TCP top-1000 plus declared/observed ports and a configurable rolling full-range sweep. Report actual port coverage and sweep age. Fragile hosts and unavailable devices have explicit coverage gaps. Public family support arrives with M3; broader discovery and UDP need a later use case.
- **FR-12** One external probe uses its own internet path, a restricted tunnel to the runner listener, pre-job vantage checks, and per-vantage observations. Its observations are trusted; it has no LAN credentials.
- **FR-14** Fixed, reviewed profiles enforce scope, traffic limits, deadlines, and cancellation. No brute force, exploit payloads, arbitrary scripts, or state-changing checks.

### History and decisions

- **FR-16** Retain assets, services, immutable observations, evidence provenance, findings, and owner decisions.
- **FR-17** Show exposure, service/version, and finding changes. Do not repeatedly notify on unchanged evidence.
- **FR-18** Resolve only with compatible newer evidence from the relevant binding and vantage, or an explicit owner action. Distinguish closed ports, repeated filtering, manual resolution, intent changes, and retirement. Missing or failed coverage is not a fix. See [contracts.md](contracts.md).
- **FR-19** Retain bounded raw output long enough for inspection and parser debugging; show when it has expired.
- **FR-28** Store owner acknowledgements, accepted risks, and false-positive decisions with reasons and precise scope. Apply them deterministically.
- **FR-39** The owner can resolve manually with a reason/evidence reference or reopen a finding. No attachment workflow is required.
- **FR-46** Accepted risks may have an owner-selected review date; false positives are invalidated by material evidence changes. No recurring renewal is required by default. Keep accepted risks visible separately.

### Vulnerability awareness

- **FR-20** Fetch KEV and selected advisory feeds daily; optionally supplement with NVD. Track source freshness and errors.
- **FR-21** Match to observed or owner-declared products and versions using explicit identifiers/aliases. Show match reason and uncertainty. Count services lacking usable product evidence; an empty match list is not a clean assessment.
- **FR-22** Matches are potentially affected warnings until supported by appropriate evidence or owner review. v1 intelligence never automatically starts checks or closes findings because a feed item disappeared.
- **FR-23** Disclosures without CVEs remain source-linked advisory items. Owner watchlist filters can surface relevant products without implying confirmed asset applicability.

### Dashboard, alerts, and API

- **FR-31** Notify on new unexpected exposure and relevant high/critical or known-exploited advisories. Group related changes, respect scoped decisions, and send one continuing incident for operational problems. Start with an ntfy-compatible HTTP POST.
- **FR-32** Offer an optional weekly digest; useful alerts and the dashboard do not depend on reading it.
- **FR-33** The built-in dashboard shows monitoring freshness, exposure, recent changes, relevant advisories, and open/accepted findings. No score or external dashboard is required.
- **FR-34** Alert on missed or persistently incomplete scheduled work. Expected sleeping clients are availability gaps, not failed scanner execution.
- **FR-35** A missing external-probe heartbeat alerts.
- **FR-36** Show last completed work, failed coverage, unavailable targets, and advisory freshness separately.
- **FR-37** A versioned API supports the dashboard's reads/actions and restricted integrations such as Hermes. It exposes no generic result importer or command execution endpoint.
- **FR-38** Owner sessions and separately revocable `read`, `scan`, and `runner` API tokens. Tokens may combine read/scan privileges within owner-selected resources. Scan authority uses approved profiles and the same budgets as schedules; it cannot modify intent, suppress findings, or administer deployment.
- **FR-45** The dashboard supports baseline declaration, scan/verify/cancel, evidence review, product labels/watchlists, decisions, and routine tuning. Core controls work with a keyboard and show text status as well as color.

### Deployment and operation

- **FR-40** Use typed internal tool/parser/notifier/feed interfaces. A public plugin API requires a concrete need; multiple implementations alone do not trigger one.
- **FR-41** Keep deployment-specific configuration and secrets outside the core. Provide a fictional example and offline validation. Export database-held assets, intent, and routine settings as one revisioned bundle.
- **FR-42** Ship versioned migrations. Test upgrades from a previous release when one exists.
- **FR-43** Automate encrypted backups of database, referenced evidence, and deployment metadata; demonstrate restore.
- **FR-44** Provide Ansible server and probe roles for existing Debian hosts, plus Compose. VM/VPS creation stays outside the core.
- **FR-47** Bound execution, prevent overlapping attempts and stale completion, deduplicate uploads, and commit findings with a durable notification outbox.
- **FR-48** Support an owner-provided external heartbeat monitor for host loss; disclose its absence. Notification failures remain visible and retry automatically.
- **FR-49** Bound scan work, pause/cancel it, and stop collection under disk pressure. Recover automatically from transient operational faults when safe.
- **FR-50** Authenticate, scope, revoke, and audit access. Escape hostile evidence, bound parsing, minimize notification data, and keep credentials out of logs and exports.

## Retired requirements

FR-6 (router import), FR-10–11 and FR-13/15 (broad assessment/compliance), FR-24–27 and FR-29–30 (built-in AI), and FR-51 (change announcements) are removed from committed scope. Useful individual extensions can receive a new scoped proposal. Historical ADRs do not reactivate them.

## Non-functional requirements

- **NFR-1–3:** self-hosted, bounded disruption, private authenticated access, and scope containment as specified in [SECURITY.md](SECURITY.md).
- **NFR-4–6:** reproducible deployment, useful logs, and isolated tests of the real operator loop.
- **NFR-7:** no required routine review, credential renewal, or Git synchronization; measure interventions in the unattended pilot.
- **NFR-8–9:** measure resource use and demonstrate backup/restore on the reference workload; do not claim unmeasured capacity or recovery guarantees.
- **NFR-10:** a readable, keyboard-usable dashboard that keeps uncertainty and freshness visible.

The execution/state rules in [contracts.md](contracts.md), trust boundaries in [SECURITY.md](SECURITY.md), and recovery behavior in [operations.md](operations.md) complete this specification.
