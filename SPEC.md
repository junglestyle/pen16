# pen15 specification

pen15 continuously assesses the security of a network you own. It scans from inside and outside, keeps history, tells you what changed and what doesn't match your intent, matches new vulnerabilities against what you actually run, and uses an LLM to triage findings and write remediation and testing playbooks that a human executes.

This document says **what** pen15 does and doesn't do. [ARCHITECTURE.md](ARCHITECTURE.md) says how. [docs/stack.md](docs/stack.md) records why each major technology was chosen.

## Goals

1. **Know your attack surface over time.** Track every host, open port, service version and finding, and surface changes rather than raw scan dumps.
2. **Compare reality to intent.** Flag anything exposed that you didn't declare, not just what changed since the last scan.
3. **See yourself from outside.** Scan public endpoints from real external vantage points, not from behind your own NAT.
4. **Catch new threats against what you run.** Match daily vulnerability intelligence to your inventory and check only the affected hosts.
5. **Prove fixes.** Every finding moves from detected to validated to remediated to verified, with evidence at each step.
6. **Never fail silently.** A scan that didn't run is an alert, not an empty diff.
7. **Be reusable.** Anyone can deploy pen15 against their own network by writing a deployment config, without forking the code.

## Non-goals

- **Automated exploitation.** pen15 never fires exploit payloads or runs proof-of-concept code. Anything beyond safe validation becomes a manual playbook for a human.
- **Scanning things you don't own.** No discovery-of-the-internet, no third-party targets, no bug-bounty mode.
- **Intrusion detection or prevention.** pen15 assesses posture on a schedule; it doesn't watch traffic or block anything.
- **Autonomous remediation.** pen15 recommends fixes; it never changes the systems it scans.
- **Multi-tenant SaaS.** One deployment serves one owner's network.
- **Wireless assessment (for now).** AP configuration audit and rogue AP detection are a roadmap item, not part of v1.
- **Code review.** Security review of source repositories is a separate roadmap product that shares pen15's finding model and API (see Roadmap).

## Users

- **Owner/operator:** deploys pen15, defines scope and expected exposure, reviews findings, runs playbooks. Primary user.
- **Integrations:** CI pipelines, external scanners and scripts that push results in or pull findings out through the API.

## Functional requirements

### Scope and intent

- **FR-1** All targets must resolve inside an operator-defined scope allowlist (CIDRs, hostnames). Targets outside scope are rejected before any tool runs, regardless of who requested them: schedule, API caller or AI agent.
- **FR-2** For dynamic public IPs published via DDNS, external jobs must confirm the DDNS name resolves to the WAN IP the deployment observes itself, and skip the job if not. A skipped job raises a health alert (FR-34).
- **FR-3** An exclude list marks fragile hosts that receive only discovery and light port scans.
- **FR-4** Every job records who requested it (schedule, user, API client, agent) and why.
- **FR-5** The deployment declares expected exposure: the services each host is meant to offer, and separately what is meant to be reachable from outside. Any observed service not declared becomes an **unexpected exposure** finding. Accepting it means adding it to the declaration, which keeps intent in version control.
- **FR-6** Optionally, router or firewall port-forward configuration can be imported as ground truth and compared with both the declaration and external scan results.

### Discovery and scanning

- **FR-7** Internal host discovery across configured networks/VLANs, over IPv4 (ARP) and IPv6 (NDP and multicast).
- **FR-8** Asset identity is composite (MAC, hostname, DHCP fingerprint, mDNS name). Randomized MACs (the locally administered bit) are detected so that a phone changing its MAC doesn't appear as a new device, and IPv6 addresses are asset attributes rather than separate assets.
- **FR-9** TCP and UDP port scanning, service and version fingerprinting (nmap).
- **FR-10** Templated vulnerability checks (nuclei, with template signature verification), TLS configuration checks, passive web-app baseline scans.
- **FR-11** Deep and authenticated network vulnerability scanning (Greenbone/OpenVAS) is available as an optional plugin, not a core dependency.
- **FR-12** External scans run from remote probes over an authenticated tunnel, and each observation records which vantage saw it. Probes must reach public targets over the internet, never via the tunnel, a subnet router or an exit node. v1 requires one untrusted vantage. Additional vantages (trusted/allowlisted, ephemeral) are optional.
- **FR-13** Compliance scans with OpenSCAP, supporting SCAP Security Guide profiles (including DISA STIG and CIS). Push mode (hosts run `oscap` and post results) is preferred; pull mode over SSH is supported.
- **FR-14** Safe validation checks may confirm a finding (for example default-credential probes against the operator's own services, or TLS downgrade tests). They must not modify target state or degrade availability.
- **FR-15** Credentials for authenticated scanning are dedicated low-privilege accounts, held only in encrypted secrets, and SSH keys are restricted by forced command and source address.

### History and change detection

- **FR-16** Persist normalized assets, services, findings and compliance results, plus every observation with its timestamp, vantage and scan run.
- **FR-17** After each run, compute diff events: asset new/gone, port opened/closed, version changed, finding new/fixed/regressed, external exposure changed, compliance rule pass/fail changed. Expected-exposure violations (FR-5) are evaluated on every run, not only on change.
- **FR-18** A finding is marked fixed only after a scan that should have detected it completes cleanly without detecting it.
- **FR-19** Raw tool output is retained for a configurable period so results can be re-parsed when parsers improve.

### Threat intelligence

- **FR-20** Daily ingestion of CISA KEV, NVD and EPSS, plus configurable news RSS feeds.
- **FR-21** Match intel items to inventory by product/version (CPE). Only CVE-backed matches can trigger scans.
- **FR-22** For each match, run an available signed check (nuclei template) against only the matched hosts. Where no check exists, record "potentially affected" with the version evidence.
- **FR-23** News items go to the human digest only. The LLM may suggest which assets a news item relates to, labeled as a suggestion, but news never triggers a scan.

### AI triage and playbooks

- **FR-24** An agent ranks diff events and findings using asset context, history and the operator's past decisions.
- **FR-25** For each confirmed finding the operator escalates, the agent produces a playbook: what the issue is and why it matters in this environment, ranked mitigations, and manual verification tests with expected before/after results.
- **FR-26** Scan-derived text (banners, HTTP titles, certificate fields, news text) is untrusted. It reaches the model only as quoted data with its provenance, never as instructions.
- **FR-27** The agent can recommend but never close, suppress or accept a finding. It cannot lower a finding's severity below the deterministic floor set by its scanner and intel data (for example KEV listing or public exposure).
- **FR-28** Operator triage decisions (accept, false positive, ignore host, and so on) are stored, applied through deterministic suppression rules, and the most relevant recent decisions are included as context in triage.
- **FR-29** The LLM backend is pluggable: local (OpenAI-compatible, for example Ollama) or hosted, with optional fallback. In strict-privacy mode, the agent waits for the local backend instead of falling back to a hosted one.
- **FR-30** Agent quality is measured against a labeled set of past findings, tracking the false-dismiss rate, and re-run whenever the model or prompts change.

### Reporting and alerting

- **FR-31** Real-time alerts for diff events above a configurable severity, via pluggable notifiers (ntfy, Pushover, email, webhook).
- **FR-32** A daily threat-intel digest and a weekly attack-surface digest.
- **FR-33** Dashboards and a scheduled remediation report (weekly or monthly, by email) with trends over time: open findings by severity, mean time to remediate per severity, share fixed within a target window, regressions, unexpected exposures, compliance pass rate, and a composite risk score. The risk score's formula is documented, and the score is always shown next to the raw counts behind it.

### Health and self-monitoring

- **FR-34** Every schedule has a dead-man switch: alert when an expected run doesn't complete successfully within its window, after a configurable number of consecutive failed or skipped runs.
- **FR-35** Probes send heartbeats, and a missing heartbeat is an alert.
- **FR-36** The dashboard shows the last successful run for each scan type and vantage, so "nothing changed" can be told apart from "nothing ran".

### API

- **FR-37** An HTTP API for starting scans, ingesting results (nmap XML, nuclei JSONL, OpenSCAP ARF/XCCDF and SARIF to start), and reading assets, findings, diffs, compliance results and playbooks.
- **FR-38** Per-client API tokens with scopes (`admin`, `agent`, `probe`, `ingest`, `read`).
- **FR-39** Manual playbook results can be submitted through the API to close or reopen a finding with evidence.

### Extensibility and operations

- **FR-40** Scanners, ingesters, notifiers, intel sources and LLM backends are plugins behind documented interfaces.
- **FR-41** All deployment-specific state (scope, expected exposure, schedules, labels, secrets, custom plugins) lives outside the core repo. The core ships an example deployment showing the required layout, and `pen15 validate` checks a deployment against the schema.
- **FR-42** Database schema changes ship as versioned migrations. Upgrade notes accompany each release.
- **FR-43** Documented backup and restore for the database and raw output, with a restore test.
- **FR-44** The core ships Ansible roles to deploy the server, probes and OpenSCAP push agents. A deployment repo deploys everything with one playbook.

## Non-functional requirements

- **NFR-1 Self-hosted:** runs on a single Docker-capable host (reference: a TrueNAS SCALE VM with 4 vCPU and 16 GB) with no required cloud services.
- **NFR-2 Low disruption:** default scan timing is polite, heavy scans run in configurable quiet windows, and fragile hosts are respected.
- **NFR-3 Secure by default:** no internet-facing UI or API; secrets are never stored in plaintext in git; probes hold no LAN credentials; jobs sent to probes are authenticated.
- **NFR-4 Reproducible:** the full deployment can be rebuilt from the deployment repo, the secrets key and a database backup.
- **NFR-5 Observable:** every job, agent decision and API call is logged, as structured logs, with its requester.
- **NFR-6 Testable:** the repo includes a fixture corpus of real tool output and an isolated lab of intentionally vulnerable targets. CI runs a full scan, diff and report cycle against the lab.

## Finding lifecycle

```
detected → validated → triaged → remediation planned → remediated → verified
                 ↘ false positive          ↘ accepted risk
```

Any closed finding that is detected again becomes **regressed**. Accepting an unexpected-exposure finding updates the deployment's expected-exposure declaration.

## Phases

| Phase | Delivers |
| --- | --- |
| 1. Inside baseline | Orchestrator, Postgres, migrations, discovery (v4 and v6), nmap and nuclei runners, scope enforcement, composite asset identity, expected exposure for internal services, diffs, alerts, dead-man switches, dashboards, `pen15 validate`, fixture corpus and lab with CI |
| 2. Outside view | One untrusted remote probe, tunnel transport and heartbeats, external scans (IPv4 and IPv6), TLS, DNS/cert monitoring, DDNS check, expected public exposure, optional router port-forward import |
| 3. Depth | OpenSCAP (push mode first) and the compliance model, ZAP baseline, findings lifecycle, credential handling, OpenVAS as an optional plugin |
| 4. AI triage | Diff triage with untrusted-input handling and severity floors, playbooks, triage decisions and suppression rules, threat-intel digest and intel-driven checks, agent evaluation set, remediation metrics dashboard and email report |
| 5. Extensions | Agent follow-up scan requests (behind a config flag), extra vantages, pseudonymizer for hosted LLM calls |

## Roadmap beyond v1

- **Code security review:** a GitHub App that runs SAST, dependency and secret scanning on PRs and comments with findings. It will get its own spec and share the finding model and ingest API.
- **Wireless:** AP configuration audit (WPA mode, WPS, guest isolation) and rogue AP detection as plugins.
- **Device coverage by class.** Each asset gets a device class (from labels or fingerprinting) that selects which checks apply:
    - **Linux:** network scans plus the OpenSCAP push agent (already in v1).
    - **macOS:** a push agent using the macOS Security Compliance Project baselines (FileVault, firewall, SIP, Gatekeeper, automatic updates), and OS version matched against Apple security releases.
    - **iOS and other locked-down devices:** no agent is possible. Network exposure checks, plus an operator-recorded OS version matched against Apple security releases.
    - **IoT and TVs (smart TVs, Alexa and similar):** network-only checks for UPnP/SSDP and mDNS exposure, debug interfaces left open (for example ADB on 5555), default credentials and firmware versions revealed by banners.
- **UPnP port-mapping audit.** Read the router's UPnP IGD mappings and flag any a device opened on its own. They become unexpected-exposure findings (FR-5, FR-6). IoT devices punching holes in the router is the most common way a home network gets exposed without anyone noticing.
- **Segmentation tests.** A probe placed inside an isolated VLAN (for example IoT) verifies it can't reach the main LAN, the NAS or management interfaces. A path that should be blocked and isn't becomes a finding.
- **Device destinations.** Optionally ingest DNS query logs (for example Pi-hole or AdGuard Home) to show which external domains each device talks to and flag new ones. This is posture data, not intrusion detection.

## Open questions

- Packaging: one compose file with profiles, or a core file plus per-phase overrides?
- Should the triage UI be a small custom app from the start, or Grafana plus API calls until phase 4?
- Expected-exposure format: per host by asset label, or per network with per-host overrides?
