# pen16 specification

pen16 is a homegrown monitor for small, self-run infrastructure: homelabs, home networks, and the devices on them. It provides security awareness and remediation channels while staying low touch, and runs mostly unattended after setup. It's deliberately straightforward, not overbuilt. Working deployment, scope controls, and recovery demonstrate useful infrastructure engineering. Core operation needs no LLM or paid service.

The threats are accidental exposure, vulnerable or forgotten services, opportunistic exploitation, and monitoring that silently stops. [SECURITY.md](SECURITY.md) maps these to controls and demonstrations.

## Dashboard

| View | Shows |
| --- | --- |
| Monitoring health | Last successful scans, notifications, backups, and later feeds/probe |
| Exposure | Reachable services and unexpected exposure by vantage |
| Recent changes | New, removed, or changed services and versions |
| Needs attention | Open findings, with accepted risks available separately |
| Relevant advisories (M2) | Potentially affected software, match reasons, and sources |
| Trends (M2) | Open findings and time to resolve over time |

Counts link to assets and findings. Show observation time, vantage, coverage, and sweep age. Asset detail includes bindings, declared/observed services, product labels, and history. Finding detail explains the evidence and resolution. Use readable text, keyboard controls, visible focus, labeled inputs, and phone-friendly layouts. Show empty, stale, and failed states explicitly.

## Requirements

- **FR-1** Validate authorized targets before dispatch and enforce scope outside the runner. Apply exclusions, fragile-host profiles, traffic ceilings, deadlines, and cancellation.
- **FR-2** Configure L2 discovery or bounded routed address/host lists. Ping each network's configured gateway before trusting negative results. Failure preserves positive evidence, blocks automatic resolution, and raises one health incident.
- **FR-3** Scan internal IPv4/TCP nightly: top-1000 plus declared/observed ports, and a fixed list of about 10 UDP ports where home devices leak (for example SSDP 1900 and mDNS 5353). Split rolling full-range sweeps into bounded chunks, targeting seven-day freshness. Show actual coverage and unavailable targets.
- **FR-4** Use owner-chosen asset IDs and static bindings; unknown devices get provisional IDs. Preserve history through corrections and retirement. IP reuse must not transfer decisions.
- **FR-5** Compare observations with expected exposure by asset/protocol/port/vantage. Bulk declarations affect selected services only; new observations never become expected automatically.
- **FR-6** Findings are open or resolved. Newer closed-port observations for every applicable binding from the same vantage resolve exposure. Filtered stays open until the owner resolves it manually. Failed or missing coverage leaves findings open. New positive evidence reopens unexpected exposure.
- **FR-7** Store settings and intent in the database; edit them in the dashboard within deployment ceilings. Support scan/verify/cancel, manual resolution/reopen, scoped accepted-risk/false-positive decisions, and history. Decisions require reasons; material evidence changes bring them back for attention.
- **FR-8** Run one job per runner with a deadline and one automatic retry. Record requester and reason. Keep immutable observations, provenance, bounded raw evidence, and job outcomes.
- **FR-9** Alert on new unexpected exposure and operational exceptions. Group related events, suppress unchanged detections, retry delivery, and show failures on the dashboard. Recover transient faults automatically and send one recovery notice.
- **FR-10** Provide a versioned API with revocable read, scan, and runner tokens and a per-token rate limit. An assistant client uses restricted read/scan access. The owner's Tailscale identity controls settings and decisions.
- **FR-11** Provide Compose, Ansible, migrations, fictional configuration, and offline validation. Automate backups, host security updates, TLS renewal, and retention. Application and tool upgrades are a deliberate pin bump and playbook run. Demonstrate restore and measure resource use and owner interventions.
- **FR-12** M2 fetches KEV and selected advisories daily, with optional NVD enrichment. Match explicit product identifiers/aliases and versions; show potentially affected assets, unmatched services, source freshness, and non-CVE watchlist items. Alert on relevant high/critical or known-exploited issues. Feeds never start scans or resolve findings; advisory resolution is an owner decision.
- **FR-13** M3 adds one external IPv4/TCP probe with independent internet egress, restricted transport, DDNS checks, and heartbeat alerts. Keep internal and external evidence separate.

## Limits

The owner, deployment host, and probe observations are trusted. Coverage depends on inventory, feeds, scan intervals, and vantage; a gateway check can miss downstream failures. Filtered ports can reflect packet loss. pen16 cannot establish that software is patched or prevent compromise. Enterprise tenancy, compliance certification, intrusion prevention, exploitation, and autonomous remediation are outside scope. Whole-host loss needs an independent monitor.

## Build order

The [roadmap](ROADMAP.md) orders the work in slices and names the requirements each delivers. M1 is v0.1: the
dashboard and internal monitoring loop, FR-1 to FR-11. M2 is FR-12 and M3 is FR-13; they can follow M1 in either
order, and together they complete v1.

## After the pilot

Deferred requirements. Each gets its own slice in the [roadmap](ROADMAP.md) once the pilot has run.

- Filtered-port heuristic.
- Routed-network witnesses.
- Request coalescing and runner-time budgets.
- Settings export/import, import preview, and optimistic revisions.
- Client housekeeping.
- UPnP port-mapping read from the router.
- IPv6 and broader UDP.
- TLS checks.
- Remediation loop: an assistant client drafts mitigations and manual tests from the read API; pen16 verifies with scan requests.
- Advisory digest and news/RSS feeds.
- Approved remediation actions.
