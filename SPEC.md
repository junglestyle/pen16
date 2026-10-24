# pen15 specification

pen15 continuously assesses the security of a network you own. It scans from inside and outside, keeps history, tells you what changed, matches new vulnerabilities against what you actually run, and uses an LLM to triage findings and write remediation and testing playbooks that a human executes.

This document says **what** pen15 does and doesn't do. [ARCHITECTURE.md](ARCHITECTURE.md) says how. [docs/stack.md](docs/stack.md) records why each major technology was chosen.

## Goals

1. **Know your attack surface over time.** Track every host, open port, service version and finding, and surface changes rather than raw scan dumps.
2. **See yourself from outside.** Scan public endpoints from real external vantage points, not from behind your own NAT.
3. **Catch new threats against what you run.** Match daily vulnerability intelligence to your inventory and check only the affected hosts.
4. **Prove fixes.** Every finding moves from detected to validated to remediated to verified, with evidence at each step.
5. **Be reusable.** Anyone can deploy pen15 against their own network by writing a deployment config, without forking the code.

## Non-goals

- **Automated exploitation.** pen15 never fires exploit payloads or runs proof-of-concept code. Anything beyond safe validation becomes a manual playbook for a human.
- **Scanning things you don't own.** No discovery-of-the-internet, no third-party targets, no bug-bounty mode.
- **Intrusion detection or prevention.** pen15 assesses posture on a schedule; it doesn't watch traffic or block anything.
- **Autonomous remediation.** pen15 recommends fixes; it never changes the systems it scans.
- **Multi-tenant SaaS.** One deployment serves one owner's network.

## Users

- **Owner/operator:** deploys pen15, defines scope, reviews findings, runs playbooks. Primary user.
- **Integrations:** CI pipelines, external scanners and scripts that push results in or pull findings out through the API.

## Functional requirements

### Scope and safety

- **FR-1** All targets must resolve inside an operator-defined scope allowlist (CIDRs, hostnames). Targets outside scope are rejected before any tool runs, regardless of who requested them: schedule, API caller or AI agent.
- **FR-2** For dynamic public IPs published via DDNS, external jobs must confirm the DDNS name resolves to the WAN IP the deployment observes itself, and skip the job if not.
- **FR-3** An exclude list marks fragile hosts that receive only discovery and light port scans.
- **FR-4** Every job records who requested it (schedule, user, API client, agent) and why.

### Discovery and scanning

- **FR-5** Internal host discovery across configured networks/VLANs, identifying assets by MAC where possible so IP changes don't create duplicates.
- **FR-6** TCP and UDP port scanning, service and version fingerprinting.
- **FR-7** Templated vulnerability checks (nuclei), deep network vulnerability scans (Greenbone/OpenVAS), TLS configuration checks, passive web-app baseline scans.
- **FR-8** External scans run from remote probes over an authenticated tunnel. A deployment can define multiple vantages (untrusted, trusted/allowlisted, ephemeral), and each observation records which vantage saw it.
- **FR-9** Compliance scans with OpenSCAP over SSH or by ingesting pushed results, supporting SCAP Security Guide profiles (including DISA STIG and CIS).
- **FR-10** Safe validation checks may confirm a finding (for example default-credential probes against the operator's own services, or TLS downgrade tests). They must not modify target state or degrade availability.

### History and change detection

- **FR-11** Persist normalized assets, services, findings and compliance results, plus every observation with its timestamp, vantage and scan run.
- **FR-12** After each run, compute diff events: asset new/gone, port opened/closed, version changed, finding new/fixed/regressed, external exposure changed, compliance rule pass/fail changed.
- **FR-13** A finding is marked fixed only after a scan that should have detected it completes cleanly without detecting it.
- **FR-14** Raw tool output is retained so results can be re-parsed when parsers improve.

### Threat intelligence

- **FR-15** Daily ingestion of CISA KEV, NVD, EPSS, GitHub Security Advisories and configurable news RSS feeds.
- **FR-16** Match intel items to inventory by product/version (CPE) first, then by LLM-assisted fuzzy matching, which is flagged as such.
- **FR-17** For each match, run an available signed check (nuclei template) against only the matched hosts. Where no check exists, record "potentially affected" with the version evidence.

### AI triage and playbooks

- **FR-18** An agent ranks diff events and findings using asset context, history and the operator's past decisions.
- **FR-19** For each confirmed finding the operator escalates, the agent produces a playbook: what the issue is and why it matters in this environment, ranked mitigations, and manual verification tests with expected before/after results.
- **FR-20** The agent may request follow-up scans only from a fixed menu of allowed actions. Every request is subject to FR-1. The agent has no shell and no direct network access.
- **FR-21** Operator triage decisions (accept, false positive, ignore host, and so on) are stored and retrieved as context for future triage.
- **FR-22** The LLM backend is pluggable: local (OpenAI-compatible, for example Ollama) or hosted, with optional fallback and optional pseudonymization of IPs and hostnames before hosted calls.

### Reporting and alerting

- **FR-23** Real-time alerts for diff events above a configurable severity, via pluggable notifiers (ntfy, Pushover, email, webhook).
- **FR-24** A daily threat-intel digest and a weekly attack-surface digest.
- **FR-25** Dashboards showing findings by severity over time, exposure changes and compliance drift.

### API

- **FR-26** An HTTP API for starting scans, ingesting results (nmap XML, nuclei JSONL, OpenSCAP ARF/XCCDF and SARIF to start), and reading assets, findings, diffs, compliance results and playbooks.
- **FR-27** Per-client API tokens with scopes (`admin`, `agent`, `probe`, `ingest`, `read`).
- **FR-28** Manual playbook results can be submitted through the API to close or reopen a finding with evidence.

### Extensibility

- **FR-29** Scanners, ingesters, notifiers, intel sources and LLM backends are plugins behind documented interfaces.
- **FR-30** All deployment-specific state (scope, schedules, labels, secrets, custom plugins) lives outside the core repo. The core ships an example deployment showing the required layout.

## Non-functional requirements

- **NFR-1 Self-hosted:** runs on a single Docker-capable host (reference: a TrueNAS SCALE VM with 4 vCPU and 16 GB) with no required cloud services.
- **NFR-2 Low disruption:** default scan timing is polite, heavy scans run in configurable quiet windows, and fragile hosts are respected.
- **NFR-3 Secure by default:** no internet-facing UI or API; secrets are never stored in plaintext in git; probes hold no LAN credentials; jobs sent to probes are authenticated.
- **NFR-4 Reproducible:** the full deployment can be rebuilt from the deployment repo plus the secrets key.
- **NFR-5 Observable:** every job, agent decision and API call is logged with its requester.

## Finding lifecycle

```
detected → validated → triaged → remediation planned → remediated → verified
                 ↘ false positive          ↘ accepted risk
```

Any closed finding that is detected again becomes **regressed**.

## Phases

| Phase | Delivers |
| --- | --- |
| 1. Inside baseline | Orchestrator, Postgres, discovery/port/nuclei runners, scope enforcement, asset and service diff, alerts, dashboards |
| 2. Outside view | Remote probe, tunnel transport, external scans (IPv4 and IPv6), TLS, DNS/cert monitoring, DDNS check |
| 3. Depth | Greenbone, ZAP baseline, OpenSCAP and compliance model, findings lifecycle, more vantages |
| 4. AI triage | Diff triage, playbooks, triage decisions, threat-intel digest and intel-driven checks |
| 5. AI planning and memory | Agent follow-up scan requests, feedback retrieval, local/hosted LLM fallback, pseudonymizer |
| Later | Code security review: a GitHub App that runs SAST, dependency and secret scanning on PRs and comments with findings |

## Open questions

- Packaging: one compose file with profiles, or a core file plus per-phase overrides?
- Should the triage UI be a small custom app from the start, or Grafana plus API calls until phase 4?
- How much of the GitHub Security Advisories feed is useful without the code-review phase?
