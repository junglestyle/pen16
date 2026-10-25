# pen15 specification

pen15 helps one homelab owner see what is exposed, what changed, and which emerging vulnerabilities may affect their software. It should be fun to build and run unattended after setup. Working deployment, scope controls, and recovery demonstrate useful infrastructure engineering. Core operation needs no LLM or paid service.

The threats are accidental exposure, vulnerable or forgotten services, opportunistic exploitation, and monitoring that silently stops. [SECURITY.md](SECURITY.md) maps these to controls and demonstrations.

## Dashboard

| View | Shows |
| --- | --- |
| Monitoring health | Last successful scans, notifications, backups, and later feeds/probe |
| Exposure | Reachable services and unexpected exposure by vantage |
| Recent changes | New, removed, or changed services and versions |
| Needs attention | Open findings, with accepted risks available separately |
| Relevant advisories (M2) | Potentially affected software, match reasons, and sources |

Counts link to assets and findings. Show observation time, vantage, coverage, and sweep age. Asset detail includes bindings, declared/observed services, product labels, and history. Finding detail explains the evidence and resolution. Use readable text, keyboard controls, visible focus, labeled inputs, and phone-friendly layouts. Show empty, stale, and failed states explicitly.

## Requirements

- **FR-1** Validate authorized targets before dispatch and enforce scope outside the runner. Apply exclusions, fragile-host profiles, traffic ceilings, deadlines, and cancellation.
- **FR-2** Configure L2 discovery or bounded routed address/host lists. Ping each network's configured gateway before trusting negative results. Failure preserves positive evidence, blocks automatic resolution, and raises one health incident.
- **FR-3** Scan internal IPv4/TCP nightly: top-1000 plus declared/observed ports. Split rolling full-range sweeps into bounded chunks, targeting seven-day freshness. Show actual coverage and unavailable targets.
- **FR-4** Use owner-chosen asset IDs and static bindings; unknown devices get provisional IDs. Preserve history through corrections and retirement. IP reuse must not transfer decisions.
- **FR-5** Compare observations with expected exposure by asset/protocol/port/vantage. Bulk declarations affect selected services only; new observations never become expected automatically.
- **FR-6** Findings are open or resolved. A newer closed-port observation from the same binding and vantage resolves exposure. Filtered stays open until the owner resolves it manually. Failed or missing coverage leaves findings open. New positive evidence reopens unexpected exposure.
- **FR-7** Store settings and intent in the database; edit them in the dashboard within deployment ceilings. Support scan/verify/cancel, manual resolution/reopen, scoped accepted-risk/false-positive decisions, and history. Decisions require reasons; material evidence changes bring them back for attention.
- **FR-8** Run one job per runner with a deadline and one automatic retry. Record requester and reason. Keep immutable observations, provenance, bounded raw evidence, and job outcomes.
- **FR-9** Alert on new unexpected exposure and operational exceptions. Group related events, suppress unchanged detections, retry delivery, and show failures on the dashboard. Recover transient faults automatically and send one recovery notice.
- **FR-10** Provide a versioned API with revocable read, scan, and runner tokens and a per-token rate limit. Hermes uses restricted read/scan access. Owner sessions control settings and decisions.
- **FR-11** Provide Compose, Ansible, migrations, fictional configuration, and offline validation. Automate backups, upgrades, TLS renewal, and retention. Demonstrate restore and measure resource use and owner interventions.
- **FR-12** M2 fetches KEV and selected advisories daily, with optional NVD enrichment. Match explicit product identifiers/aliases and versions; show potentially affected assets, unmatched services, source freshness, and non-CVE watchlist items. Alert on relevant high/critical or known-exploited issues. Feeds never start scans or resolve findings; advisory resolution is an owner decision.
- **FR-13** M3 adds one external IPv4/TCP probe with independent internet egress, restricted transport, DDNS checks, and heartbeat alerts. Keep internal and external evidence separate.

## Limits

The owner, deployment host, and probe observations are trusted. Coverage depends on inventory, feeds, scan intervals, and vantage; a gateway check can miss downstream failures. Filtered ports can reflect packet loss. pen15 cannot establish that software is patched or prevent compromise. Enterprise tenancy, compliance certification, intrusion prevention, exploitation, and autonomous remediation are outside scope. Whole-host loss needs an independent monitor.

## Milestones

All milestones are planned and incomplete.

| Milestone | Deliver and demonstrate |
| --- | --- |
| M0 | Package, lockfile, CI, configuration, initial migration; one fixture becomes an unexpected-exposure finding |
| M1 / v0.1 | FR-1–11: dashboard, internal monitoring, restricted API, alerts, deployment, and recovery |
| M2 | FR-12: relevant, unrelated, ambiguous, stale, and duplicate advisory fixtures |
| M3 | FR-13: external scope, egress/DDNS checks, lost-probe alerts, and vantage separation |

M2 and M3 can follow M1 in either order; together they complete v1.

M1 demo:

1. Bring up the fictional lab and private dashboard.
2. Scan and inspect discovered services.
3. Bulk-declare selected services expected.
4. Open an unexpected port.
5. Receive one alert, close the port, and verify resolution.

Also demonstrate scope containment, filtered/unavailable results staying open, cancellation/deadlines, denied assistant actions, notification failure, and restored evidence/settings. Run a four-week unattended pilot; record setup effort, resource use, nuisance alerts, and interventions. Remove recurring chores before adding integrations.

## After the pilot

- Filtered-port heuristic.
- Routed-network witnesses.
- Request coalescing and runner-time budgets.
- Settings export/import, import preview, and optimistic revisions.
- Client housekeeping.
- UPnP port-mapping read from the router.
- IPv6/UDP.
- TLS checks.
- Approved remediation.
