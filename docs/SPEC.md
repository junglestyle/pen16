# pen15 specification

pen15 is designed to continuously assess a homelab network you own, with low ongoing operator effort. It scans from inside and outside, keeps history, tells you what changed and what doesn't match your intent, and matches new vulnerabilities against what you actually run. Optional later AI assistance writes triage recommendations and playbooks that a human executes.

This document says **what** pen15 does and doesn't do. [ARCHITECTURE.md](ARCHITECTURE.md) says how. [stack.md](stack.md) records why each major technology was chosen.

All requirements describe intended behavior, not implemented features. [product.md](product.md) defines the audience and success targets; [PLAN.md](PLAN.md) assigns requirements to releases and defers optional capabilities beyond v1. [UX.md](UX.md), [contracts.md](contracts.md), [SECURITY.md](SECURITY.md), and [operations.md](operations.md) provide the normative interaction, correctness, safety, and recovery details.

## Goals

1. **Know your attack surface over time.** Track every host, open port, service version and finding, and surface changes rather than raw scan dumps.
2. **Compare reality to intent.** Flag anything exposed that you didn't declare, not just what changed since the last scan.
3. **See yourself from outside.** Scan public endpoints from real external vantage points, not from behind your own NAT.
4. **Catch new threats against what you run.** Match daily vulnerability intelligence to your inventory and check only the affected hosts.
5. **Prove fixes.** Every finding moves from detected to validated to remediated to verified, with evidence at each step.
6. **Never fail silently.** A scan that didn't run is an alert, not an empty diff.
7. **Be reusable.** Deployment-specific configuration stays outside the core; adopting pen15 should not require a fork.
8. **Stay low maintenance.** Target a short weekly review after setup, with useful grouped notifications, automated health checks and backups, and optional heavy integrations. Measure operator effort in the pilot.

## Non-goals

- **Automated exploitation.** pen15 never fires exploit payloads or runs proof-of-concept code. Anything beyond safe validation becomes a manual playbook for a human.
- **Scanning things you don't own.** No discovery-of-the-internet, no third-party targets, no bug-bounty mode.
- **Intrusion detection or prevention.** pen15 assesses posture on a schedule; it doesn't watch traffic or block anything.
- **Autonomous remediation.** pen15 recommends fixes; it never changes the systems it scans.
- **Multi-tenant SaaS.** One deployment serves one owner's network.
- **Wireless assessment (for now).** AP configuration audit and rogue AP detection are a roadmap item, not part of v1.
- **Code review.** Security review of source repositories is a separate roadmap product that shares pen15's finding model and API (see Roadmap).

## Users

- **Owner/operator:** a technically comfortable homelab owner who deploys pen15, defines scope and expected exposure, reviews findings, and runs playbooks. One owner per deployment is the initial design; routine work should fit a short weekly review.
- **Integrations:** CI pipelines, external scanners and scripts that push results in or pull findings out through the API.

## Functional requirements

### Scope and intent

- **FR-1** All targets must resolve inside an operator-defined scope allowlist (CIDRs, hostnames). Targets outside scope are rejected before any tool runs, regardless of who requested them: schedule, API caller or AI agent.
- **FR-2** For dynamic public IPs published via DDNS, external jobs must confirm the DDNS name resolves to the WAN IP the deployment observes itself, and skip the job if not. A skipped job raises a health alert (FR-34).
- **FR-3** An exclude list marks fragile hosts that receive only discovery and light port scans.
- **FR-4** Every job records who requested it (schedule, user, API client, agent) and why.
- **FR-5** The deployment declares expected exposure: the services each host is meant to offer, and separately what is meant to be reachable from outside. Any observed service not declared becomes an **unexpected exposure** finding. Declaring it expected generates a patch for the owner's private deployment repo; only validated activation of the committed declaration resolves the policy violation, with reason `intent_changed`. The application does not write Git commits. Initial declarations use stable asset IDs; selector precedence is deferred.
- **FR-6** Optionally, router or firewall port-forward configuration can be imported as a separate configuration source and compared with both declared intent and external observations. Imported configuration is not proof of actual reachability.

### Discovery and scanning

- **FR-7** Internal host discovery across configured networks/VLANs, over IPv4 (ARP) and IPv6 (NDP and multicast).
- **FR-8** Asset identity uses available MAC, hostname, authenticated identity, DHCP and mDNS evidence. Locally administered MACs are weak evidence and do not guarantee continuity. Ambiguous matches remain separate pending owner review; merge/split corrections preserve evidence and audit history. IPv4/IPv6 addresses are time-bounded asset bindings, and IP reuse must not transfer findings to another device.
- **FR-9** TCP and UDP port scanning, service and version fingerprinting (nmap).
- **FR-10** Templated vulnerability checks (nuclei, with template signature verification), TLS configuration checks, passive web-app baseline scans.
- **FR-11** Deep and authenticated network vulnerability scanning (Greenbone/OpenVAS) is available as an optional plugin, not a core dependency.
- **FR-12** External scans run from remote probes over an authenticated tunnel, and each observation records which vantage saw it. Probes must reach public targets over the internet, never via the tunnel, a subnet router or an exit node. v1 requires one untrusted vantage. Additional vantages (trusted/allowlisted, ephemeral) are optional.
- **FR-13** Compliance scans with OpenSCAP, supporting SCAP Security Guide profiles (including DISA STIG and CIS). Push mode (hosts run `oscap` and post results) is preferred; pull mode over SSH is supported.
- **FR-14** Only explicitly reviewed, pinned, bounded validation checks may confirm a finding. Signatures alone do not establish scan safety. Default-credential/login attempts, brute force, exploit payloads, and state-changing checks are disabled. Later authenticated read-only profiles require explicit credential and disruption policies. Fragile-host restrictions, cancellation, and per-target traffic limits apply to every runner.
- **FR-15** Credentials for authenticated scanning are dedicated low-privilege accounts, held only in encrypted secrets, and SSH keys are restricted by forced command and source address.

### History and change detection

- **FR-16** Persist normalized assets, services, findings and compliance results, plus every observation with its timestamp, vantage and scan run.
- **FR-17** After each run, compute diff events: asset new/gone, port opened/closed, version changed, finding new/fixed/regressed, external exposure changed, compliance rule pass/fail changed. Expected-exposure violations (FR-5) are evaluated on every run, not only on change.
- **FR-18** Automatic verification requires newer successful negative evidence from the relevant asset/service/check/vantage/address-family coverage, under compatible detection semantics. Failed, omitted, filtered, unsupported, or unreachable coverage cannot establish a fix. Manual verification and intent changes are separate audited resolution reasons, never disguised as a passing scan.
- **FR-19** Raw tool output is retained for a configurable period so results can be re-parsed when parsers improve.

### Threat intelligence

- **FR-20** Daily ingestion of CISA KEV, NVD and EPSS, plus configurable news RSS feeds.
- **FR-21** Match intel items to inventory by product/version (CPE). Only CVE-backed matches can trigger scans.
- **FR-22** For each match, run an available signed and explicitly approved check (nuclei template) against only the matched hosts. Where no approved check exists or version evidence is uncertain, record "potentially affected" with the evidence and confidence.
- **FR-23** News items go to the human digest only. The LLM may suggest which assets a news item relates to, labeled as a suggestion, but news never triggers a scan.

### AI triage and playbooks

- **FR-24** An agent ranks diff events and findings using asset context, history and the operator's past decisions.
- **FR-25** For each confirmed finding the operator escalates, the agent produces a playbook: what the issue is and why it matters in this environment, ranked mitigations, and manual verification tests with expected before/after results.
- **FR-26** Scan-derived text (banners, HTTP titles, certificate fields, news text) is untrusted. It reaches the model only as quoted data with its provenance, never as instructions.
- **FR-27** The agent can recommend but never close, suppress or accept a finding. It cannot lower a finding's severity below the deterministic floor set by its scanner and intel data (for example KEV listing or public exposure).
- **FR-28** Operator triage decisions (accept, false positive, ignore host, and so on) are stored, applied through deterministic suppression rules, and the most relevant recent decisions are included as context in triage.
- **FR-29** The optional LLM backend is pluggable: local (OpenAI-compatible, for example Ollama) or hosted through an adapter, with separately configured fallback. Local inference is the default; hosted use requires explicit allowed fields, destination, and spending limits. Strict-privacy mode prohibits hosted fallback. Model failure never blocks monitoring or manual triage.
- **FR-30** Agent quality is measured against a labeled set of past findings, tracking the false-dismiss rate, and re-run whenever the model or prompts change.

### Reporting and alerting

- **FR-31** Real-time alerts for diff events above a configurable severity, via pluggable notifiers (ntfy, Pushover, email, webhook).
- **FR-32** A daily threat-intel digest and a weekly attack-surface digest.
- **FR-33** Optional later dashboards and a scheduled remediation report (weekly or monthly, by email) show open findings by severity, mean time to remediate, share fixed within a configured target window, regressions, unexpected exposures, and compliance pass rate where supported. Distinguish manual verification, accepted risk, intent changes, and stale coverage. A composite score is optional and ships only after its usefulness is established, with a versioned formula and raw counts alongside it.

### Health and self-monitoring

- **FR-34** Every schedule has a dead-man switch: alert when an expected run doesn't complete successfully within its window, after a configurable number of consecutive failed or skipped runs.
- **FR-35** Probes send heartbeats, and a missing heartbeat is an alert.
- **FR-36** The dashboard shows the last successful run for each scan type and vantage, so "nothing changed" can be told apart from "nothing ran".

### API

- **FR-37** A versioned HTTP API for starting scans, ingesting supported results, and reading assets, findings, diffs, and later compliance results/playbooks. Start with nmap XML; add nuclei JSONL and OpenSCAP ARF/XCCDF with their milestones. SARIF waits for a defined importer/use case. Unsupported formats fail explicitly.
- **FR-38** Per-client API tokens with scopes (`admin`, `agent`, `probe`, `ingest`, `read`).
- **FR-39** An authorized owner can submit manual verification evidence or reopen a finding through the UI/API. Closure records `manual_verification`, the covered subjects, actor, and reason; it never fabricates scan coverage. Marking remediated alone leaves verification pending. An agent cannot use this authority.

### Extensibility and operations

- **FR-40** Scanners, ingesters, notifiers, intel sources and LLM backends are plugins behind documented interfaces.
- **FR-41** All deployment-specific state (scope, expected exposure, schedules, labels, secrets, custom plugins) lives outside the core repo. The core ships an example deployment showing the required layout, and `pen15 validate` checks a deployment against the schema.
- **FR-42** Database schema changes ship as versioned migrations. Upgrade notes accompany each release.
- **FR-43** Documented backup and restore for the database and raw output, with a restore test.
- **FR-44** The core ships Ansible roles to deploy the server, probes and OpenSCAP push agents. A deployment repo deploys everything with one playbook.
- **FR-45** The built-in UI supports onboarding, scan/cancel, evidence review, expected-intent patch export, triage decisions, and verification. Empty, stale, failed, and uncertain states are explicit; core actions support keyboard use and do not require Grafana or hand-written API calls.
- **FR-46** Accepted-risk and false-positive decisions require a reason, scope, owner, and expiry. Expiry or material evidence changes prompt review without erasing prior observations. Decision state is separate from remediation state.
- **FR-47** Jobs use bounded leases, deadlines, fencing, and retries. Ingestion is idempotent; late/duplicate results cannot reverse newer state or duplicate logical events. State updates and notification-outbox entries commit together.
- **FR-48** An independent watchdog can detect whole-server loss and an unhealthy notification pipeline. Without one, setup and the UI disclose this blind spot. Delivery failures are durable, retried, and visible.
- **FR-49** Pause/cancel controls stop or bound ongoing work; scan profiles enforce approved checks, egress scope, traffic/concurrency limits, and quiet windows. Disk pressure pauses collection rather than silently deleting required evidence.
- **FR-50** Human sessions and API identities are authenticated, scoped, revocable, and audited. Probe and ingest access is bound to enrolled resources. Raw evidence, logs, notifications, and hosted inference follow the documented data-minimization policy.

## Non-functional requirements

- **NFR-1 Self-hosted:** runs on a single Docker-capable host (reference: a Debian 13 VM on TrueNAS SCALE with 4 vCPU and 16 GB) with no required cloud services.
- **NFR-2 Low disruption:** default scan timing is polite, heavy scans run in configurable quiet windows, and fragile hosts are respected.
- **NFR-3 Secure by default:** no internet-facing UI or API; secrets are never stored in plaintext in git; probes hold no LAN credentials; jobs sent to probes are authenticated.
- **NFR-4 Reproducible:** the full deployment can be rebuilt from the deployment repo, the secrets key and a database backup.
- **NFR-5 Observable:** every job, agent decision and API call is logged, as structured logs, with its requester.
- **NFR-6 Testable:** the repo includes a fixture corpus of real tool output and an isolated lab of intentionally vulnerable targets. CI runs a full scan, diff and report cycle against the lab.
- **NFR-7 Low effort:** proposed pilot target of at most 15 minutes of routine review/configuration per week over four weeks, excluding setup and incident remediation. Measure alert usefulness and onboarding time as defined in [product.md](product.md).
- **NFR-8 Bounded resources:** validate the core against the 100-asset/4-network reference envelope with recorded peak resources and growth. Enforce the proposed limits in [operations.md](operations.md); optional components have separate budgets.
- **NFR-9 Recoverable:** target a 24-hour recovery point and 2-hour restore for the reference workload; demonstrate consistent backup/restore and migration recovery before claiming these objectives are met.
- **NFR-10 Accessible and honest:** core workflows support keyboard operation, readable labels/status, and escaped evidence. Freshness and coverage remain visible independently of finding counts or scores.

## Finding lifecycle

Typical workflow: `detected → validated → triaged → remediation_planned → remediated → verified`. Intermediate review steps can be skipped under the allowed transitions in [contracts.md](contracts.md); marking remediated is an owner claim, not verification.

Accepted risk and false positive are expiring decisions separate from workflow state. A fresh detection after verified resolution emits a `regressed` event and reopens the finding, subject to the current expected-exposure policy. Resolution reasons distinguish a passing check, manual verification, and an activated intent change. The transition table, evidence rules, and per-vantage semantics in [contracts.md](contracts.md) are authoritative.

## Delivery

[PLAN.md](PLAN.md) is the single milestone plan: foundation; usable internal loop (v0.1); broader internal coverage; outside view; structured intelligence (v1); optional depth; optional AI/reporting; extensions. Each milestone states dependencies, acceptance evidence, and deferrals. Basic finding lifecycle and decisions ship with the first operator loop, not with a later scanner integration.

## Roadmap beyond v1

- **Code security review:** a GitHub App that runs SAST, dependency and secret scanning on PRs and comments with findings. It will get its own spec and share the finding model and ingest API.
- **Wireless:** AP configuration audit (WPA mode, WPS, guest isolation) and rogue AP detection as plugins.
- **Device coverage by class.** Each asset gets a device class (from labels or fingerprinting) that selects which checks apply:
    - **Linux:** network scans plus the optional OpenSCAP push agent (M5).
    - **macOS:** a push agent using the macOS Security Compliance Project baselines (FileVault, firewall, SIP, Gatekeeper, automatic updates), and OS version matched against Apple security releases.
    - **iOS and other locked-down devices:** no agent is possible. Network exposure checks, plus an operator-recorded OS version matched against Apple security releases.
    - **Routers:** the router is both a target (admin UI or SSH reachable from WAN, cloud features enabled, firmware against vendor advisories) and a data source (port forwards and UPnP mappings, read-only over SSH, as an `exposure_source` plugin; Asuswrt-Merlin first).
    - **IoT and TVs (smart TVs, Alexa and similar):** network-only checks for UPnP/SSDP and mDNS exposure, debug interfaces left open (for example ADB on 5555), and firmware versions revealed by banners. Credential-guessing probes remain disabled under FR-14.
- **UPnP port-mapping audit.** Read the router's UPnP IGD mappings and flag any a device opened on its own. They become unexpected-exposure findings (FR-5, FR-6). IoT devices punching holes in the router is the most common way a home network gets exposed without anyone noticing.
- **Segmentation tests.** A probe placed inside an isolated VLAN (for example IoT) verifies it can't reach the main LAN, the NAS or management interfaces. A path that should be blocked and isn't becomes a finding.
- **Device destinations.** Optionally ingest DNS query logs (for example Pi-hole or AdGuard Home) to show which external domains each device talks to and flag new ones. This is posture data, not intrusion detection.

## Decisions and remaining validation

Use one core Compose file with optional profiles, a small built-in operator UI, and per-asset declarations initially. Label/network selector precedence is deferred until its merge rules are specified and tested. See [stack.md](stack.md) for these decisions.

Pilot work must establish actual setup/review effort, alert usefulness, safe profile defaults, resource needs, and whether a composite score adds value. These are measured acceptance questions, not reasons to broaden the first release.
