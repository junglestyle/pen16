# Delivery plan

All milestones are planned and incomplete. This plan replaces the original broad feature phases with independently verifiable increments. The maintainer is the accepting operator; contributors can own individual issues. Dependencies and exit evidence determine sequence, not dates.

v0.1 is the usable internal-monitoring milestone M1. v1 includes M2–M4 after their gates pass. M5–M7 are optional later increments; in particular AI, compliance, and a risk score are not prerequisites for useful monitoring. [SPEC.md](SPEC.md) retains the full intended feature set, with this plan defining when each part ships.

## Requirement coverage

Requirements spanning integrations are delivered incrementally; a milestone does not claim unsupported protocols or plugins. Safety, observability, and correctness requirements apply to every increment.

| Milestone | Principal requirements |
| --- | --- |
| M0 | FR-40–42 foundations; NFR-6 development/test harness |
| M1 | FR-1, 3–5, 7–9 (IPv4/TCP), 16–19, 28 (decisions), 31–32 (webhook/weekly), 34, 36–43 (core API/operations), 44 (server), 45–50; NFR-1–10 for delivered scope |
| M2 | FR-7/9 (IPv6/UDP), 8 (device classes), 10 (nuclei), 14; broader NFR-2/6/8 evidence |
| M3 | FR-2, 5 (public intent), 10 (TLS), 12, 35, 44 (probe); external-scope NFR-3/5/6 |
| M4 | FR-20–23, 32 (daily intelligence); v1 validation of NFR-1–10 |
| M5 | FR-10 (web baseline), 11, 13–15, 16–17/37 (compliance), 44 (OpenSCAP agent) |
| M6 | FR-24–30 (AI), 31 (additional notifiers), 33 (advanced reporting) |
| M7 | FR-6 (router import), optional additional vantages, and separately specified roadmap work |

## M0 — Development and contract foundation

**Depends on:** accepted documentation in this repository.

Deliver the Python package/lockfile, formatter/linter/type/test configuration, CI, `.gitignore`, developer quickstart, typed configuration and normalized models, initial migrations, and isolated test harness. Implement schema validation and the initial scope/profile/coverage/lifecycle contracts. Add a fictional deployment example; no live network scans run in CI.

**Exit evidence:** a fresh checkout can run the documented checks; invalid/out-of-scope configuration fails with useful errors; migrations create an empty database; a fixture can pass through normalization and produce a deterministic finding. Documentation/link checks run in CI. Record a runnable demo command and test output in the milestone issue.

## M1 — Complete internal operator loop / v0.1

**Depends on:** M0.

Deliver bounded IPv4 discovery/TCP service observation with nmap, scope and egress enforcement, conservative asset identity, per-asset expected exposure, coverage-aware diffs, basic lifecycle/decisions, owner authentication, a minimal operator UI, targeted verification, scheduling, one webhook notifier, weekly digest, durable outbox, local health and external watchdog integration. Package core Compose and the Ansible server role. Include backup/restore and an initial upgrade procedure.

**Demo:** configure the isolated lab → validate/preflight → scan → inspect a service → export and activate expected intent → introduce an unexpected port → receive one grouped alert → close the port → verify resolution. Repeat with a failed verification: the finding must remain open. Demonstrate accepted risk and its expiry, cancellation, and an offline host.

**Exit evidence:** the demo is repeatable without SQL/manual HTTP calls; contract fixtures for partial results, identity ambiguity, duplicate ingestion, worker recovery, and late data pass; out-of-scope egress is blocked; a server outage triggers the independent watchdog; backup restores with evidence intact. Run the 10-asset onboarding timing and start the 4-week maintenance/alert-quality pilot. Publish measured results and limitations before tagging v0.1; unmet targets require an explicit documented adjustment, not an unsupported success claim.

**Deferred:** automatic cross-network identity inference, label-based intent precedence, UDP/IPv6, vulnerability templates, external probes, compliance, AI, Grafana, and composite scores.

## M2 — Broader internal coverage

**Depends on:** M1 and its initial pilot evidence.

Deliver IPv6 discovery/address coverage, bounded UDP checks, approved signed nuclei templates, per-tool severity mappings, supported scanner/parser version fixtures, and the reviewed check manifest. Add device-class labels without assuming every platform supplies fingerprint data. Define version-match uncertainty before exposing vulnerability matches as confirmed findings.

**Exit evidence:** dual-stack fixtures never resolve an issue from only one family's result; unavailable UDP services are not assumed closed; unsigned/unapproved templates are rejected; parser/version changes cannot silently resolve findings. Benchmark the reference 100 assets/4 networks and record peak memory, runtime, storage growth, and any unsupported coverage. Confirm resource and scan-disruption limits in the lab before enabling the profiles on the homelab.

## M3 — External perspective

**Depends on:** M2.

Deliver one external probe, its Ansible role, signed expiring jobs, enrollment/revocation, object-scoped uploads, tunnel ACLs, heartbeats, public IPv4/IPv6 scope, DDNS validation, external expected exposure, and TLS checks. Define DNS/certificate expiry/change observations and severity before enabling their alerts. Router port-forward import remains optional follow-up work.

**Exit evidence:** prove the probe reaches the public target over its own internet route, DDNS mismatch skips safely, redirects cannot escape scope, a lost probe alerts, and an internal clean scan cannot resolve an external finding. Test replay, expired jobs, revoked/cross-probe credentials, and disconnected-runner deadlines. Document the optional VPS cost and setup effort.

## M4 — Structured intelligence / v1

**Depends on:** M2 and M3 for v1 release.

Deliver KEV/NVD/EPSS ingestion, provenance/freshness, deterministic CPE/version matches with confidence, approved targeted checks, and a daily intel digest. News can appear in the digest but never starts scans. Keep matching usable without an LLM. Add provider quotas, bounded retries, cached data, and a stale-feed health condition. Map severity floors explicitly before release.

**Exit evidence:** a known affected service matches and receives only its approved check; uncertain versions remain potentially affected; unrelated assets receive no job; duplicate/stale feed data causes neither a scan storm nor false resolution. Re-run the maintenance/alert pilot and core restore/failure checks against the release candidate. Publish supported versions, actual resource measurements, and known blind spots.

## M5 — Optional assessment depth

**Depends on:** v1 contracts; each integration can ship independently.

Deliver OpenSCAP push enrollment and Ansible role, compliance result semantics, ZAP baseline, then optional authenticated pull/OpenVAS profiles. Keep these opt-in and document extra resources and credential handling.

**Exit evidence:** each integration passes its parser, scope, disruption, authorization, and unavailable-target fixtures; compliance not-applicable/error is distinct from pass/fail; missing credentials cannot look like a clean assessment. No integration is marked supported without a repeatable lab demonstration.

## M6 — Optional AI assistance and richer reporting

**Depends on:** v1 and retained, labeled operator decisions. Compliance metrics additionally depend on M5.

Deliver bounded recommendation/playbook generation, local-first backend selection, explicit hosted data/spend policy, and evaluation fixtures. Add optional Grafana views and remediation email reports from the same versioned metric definitions. A composite score ships only if the pilot establishes that it adds useful information beside counts/freshness.

**Exit evidence:** compare deterministic-only review with assisted review on a versioned labeled corpus; use at least 50 labeled cases including at least 10 adversarial-input cases. Define false dismissal as labeling an actionable issue ignorable or omitting it from the actionable report. Require zero false dismissals of high/critical cases and at most 5% overall; report denominators and limitations, never claim these samples prove safety. Permissions must prevent every attempted finding mutation. Demonstrate unavailable-model operation, forbidden hosted fallback, budget exhaustion, grounded playbooks, and consistent dashboard/email metrics. Re-run on prompt/model changes.

## M7 — Extensions

**Depends on:** accepted core milestones and a specific operator need.

Extra vantages, label-based declarations, router imports, wireless, segmentation tests, additional device agents, and hosted-context pseudonymization each require a small scoped proposal and lab evidence. Agent follow-up scans require a separate permission/capability design and approved fixed action menu before enabling the config flag. Code security review remains a separate product/spec.

## Completion and change control

Each milestone issue records its owner, dependencies, linked FR/NFR requirements, implementation PRs, demonstration instructions, test results, measured targets, known gaps, and acceptance decision. Create implementation issues as work is scheduled; this document is not evidence they already exist.

Safety/correctness gates cannot be traded for more feature coverage. Product timing/resource targets may be revised with measured evidence and a documented decision. Keep [stack decisions](stack.md), [contracts](contracts.md), and [the operator experience](UX.md) consistent when scope changes; don't leave an older phase table as a competing source of truth.
