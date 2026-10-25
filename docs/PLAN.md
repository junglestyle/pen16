# Delivery plan

All milestones are planned and incomplete. Deliver a useful dashboard early, then add vulnerability awareness and the outside view. M1 is v0.1; v1 includes M2 and M3, which can follow M1 in either order. This replaces the earlier M0–M7 plan; milestone numbers in historical ADRs are not current commitments.

## Requirement coverage

The retained IDs are defined in [SPEC.md](SPEC.md). Safety and correctness apply at every milestone. Features outside this table have no delivery commitment.

| Milestone | Requirements |
| --- | --- |
| M0 | FR-40–42 foundations; development harness |
| M1 / v0.1 | FR-1, 3–5, 7–9 (internal IPv4/TCP), 14, 16–19, 28, 31–33, 34, 36–50 for the internal deployment |
| M2 | FR-20–23; advisory portions of FR-31–33 and FR-45 |
| M3 / v1 | FR-2, 5 (public exposure), 9 (public TCP, enabled address families), 12, 35, 44 (probe); external portions of FR-18, 38, 47, 49–50 |

## M0 — Runnable foundation

Add the Python package, lockfile, lint/type/test commands, CI, initial database migration, typed configuration, and fictional deployment. Keep interfaces internal. Use recorded nmap output and small isolated listeners; no live network scans in CI.

**Done when:** a fresh checkout runs its checks, invalid scope is rejected, and one fixture becomes a service observation and unexpected-exposure finding. Keep this scaffold small enough to proceed directly to M1.

## M1 — Dashboard and internal monitoring

**Depends on:** M0.

Deliver one nmap pull runner, Postgres, a server-rendered dashboard, and an API for the same actions. Include internal IPv4/TCP discovery, expected services, history, targeted verification, schedules, one ntfy-compatible notifier, optional weekly digest, and monitoring health. The dashboard supports bulk baseline declarations, precise mute/accept decisions, and routine tuning.

An assistant such as Hermes can use a resource-restricted `read`/`scan` token. It can inspect evidence and request approved bounded scans; it cannot change scope, declare exposure expected, suppress findings, or run commands. This API needs no built-in model or Hermes-specific service.

Ship Compose and the Ansible server role, private TLS with automatic renewal, host-owned scan egress rules, nightly backups, and a restore procedure. Scope changes remain deployment operations. Other routine tuning stays in the dashboard.

**Demonstration:** set up the lab → scan → bulk-declare expected services → introduce an unexpected port → receive one alert and inspect the dashboard → restrict it → verify. Exercise both a closed port and the documented filtered-port heuristic. Also show a sleeping client, a failed scan path, a denied assistant action, and restored evidence and settings.

**Release evidence:** scope restrictions hold for raw traffic, cancellation/deadlines bound work, duplicate or late results do not reverse state, partial evidence stays explicit, and notification failures are visible. Demonstrate an optional external monitor detecting host loss. Start an unattended pilot and publish actual setup effort, resource use, and limitations; implementation need not wait four weeks before becoming useful.

## M2 — Lightweight vulnerability awareness

**Depends on:** M1.

Fetch CISA KEV daily and follow a small owner-selected set of vendor/security advisory feeds. Match structured product data where available; use explicit product aliases and an owner-maintained software watchlist when banners are insufficient. NVD is supplementary enrichment. Preserve source, update time, match reason, and uncertainty. News without a CVE can still surface as an advisory; it never launches a scan or becomes proof of exploitability.

Show potentially affected assets, unmatched services, stale feeds, and important unmatched advisories on the dashboard. Alert on new relevant known-exploited or high/critical advisories; group other updates. No vulnerability scanner, LLM, exploit validation, or complete CPE inventory is required.

**Done when:** a seeded advisory matches relevant inventory, an ambiguous version remains uncertain, an unrelated product is not matched, and stale/duplicate feeds neither clear warnings nor repeatedly alert. A disclosure without a CVE remains available for human review. Demonstrate an owner correcting a product label without editing the database.

## M3 — External perspective and v1

**Depends on:** M1. Release v1 after M2 and M3 are usable.

Add one external probe with the same restricted runner protocol, an Ansible role, public scope and DDNS checks, independent internet egress, and a heartbeat. Support each explicitly enabled public address family; show disabled families as unmonitored. Reuse the dashboard, notifier, API authorization, and job deadlines.

**Done when:** the probe cannot reach owner routes or LAN services through its tunnel policy; pre-job checks catch wrong egress and DDNS mismatch; lost probes alert; and internal observations cannot resolve external findings. Demonstrate expired/replayed assignments, revocation, and a disconnected probe stopping at its deadline. Measure provider costs and setup effort.

## Later, only when useful

Possible additions include broader IPv6/UDP discovery, a few approved vulnerability checks, TLS assessment, router configuration import, and assistant-written explanations. No public plugin framework, compliance suite, Grafana dependency, composite risk score, or built-in AI runtime is promised.

API-triggered remediation is a separate future increment. Start with a small owner-chosen action on a named resource, an inspectable plan, explicit approval, bounded execution, and verification or rollback evidence. Give it separate authorization from `scan`. Do not expose arbitrary shell commands or let untrusted scan/advisory text approve actions. Specify the first real use case before designing a general remediation engine.

## Evidence and change control

Each milestone needs a reproducible demo, relevant failure tests, measured operating effort, and a short explanation of accepted risks. A design change updates the relevant docs and [ADRs](stack.md). Prefer deleting a feature over adding a recurring chore to sustain it. The project demonstrates engineering judgment through working boundaries and recovery, not the number of integrations.
