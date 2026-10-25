# Security and scan-safety design

This document specifies controls to implement and test. It is not a claim that the design-stage repository already enforces them. Responsible use covers only the operator's explicitly authorized networks. Automated exploitation and autonomous remediation remain out of scope.

## Assets and trust boundaries

Protect the owner's network, scan credentials, network inventory, retained evidence, signing keys, and integrity of findings. Assume a scanned service can return malicious data, an uploaded result can be malformed, an API credential can be stolen, and a remote probe can be compromised. LAN/tunnel reachability is not authentication. The deployment host administrator is trusted; full host compromise is outside the containment guarantee and requires credential rotation and rebuild.

| Boundary | Threat | Required control and verification |
| --- | --- | --- |
| Request/configuration → job | Out-of-scope or unbounded scan | Typed profiles, target manifest, exclusions, limits, dispatch-time scope checks; rejection fixtures |
| Runner → network | DNS change, redirect, generated URL, or plugin expands scope | Pinned target addresses and enforced per-job egress policy; lab attempts to contact a forbidden address must fail |
| Probe → API | Stolen probe credential reads inventory or submits another probe's work | Object-bound capabilities and endpoint ACLs; cross-probe negative authorization tests |
| Raw output → parser/store/UI | Resource exhaustion, external entity resolution, path traversal, or injected markup | Bounded streaming parsers, disabled external resolution, generated paths, escaped display; malicious fixtures |
| Evidence → model/provider | Prompt injection or inventory disclosure | Bounded structured context, explicit egress policy, output validation, no finding-mutation authority; adversarial evaluations |
| Application → container runtime | API/plugin input becomes host execution authority | Restricted launcher interface and approved image/capability policy; rejection tests |

## Scope and network enforcement

Canonicalize IPv4/IPv6 addresses and hostnames; reject malformed, ambiguous, or overly large expansions. Resolve all relevant address records during planning and revalidate at dispatch. Preserve intended DNS name/SNI while pinning connections to approved addresses. If any target resolution is outside the approved policy, reject the target and show why; do not silently broaden scope. DDNS external jobs additionally compare against the deployment-observed public addresses for each enabled family.

Disable redirects and automatic target expansion by default. An adapter enabling them must validate every destination and enforce the same address policy at connection time. Templates, browser resources, callbacks, and discovered links are not implicitly authorized. Disable out-of-band callback services unless separately designed and approved in a future milestone.

Use a per-job network policy that allows only the resolved target set and the minimum explicitly named infrastructure dependencies. Scanner egress must not include the orchestrator, database, container runtime, host metadata endpoints, or other networks by default. Profiles needing layer-2 discovery receive an explicit interface/network boundary. Scope changes cancel affected queued jobs and revoke/restrict running jobs; probes enforce signed expiry and local limits even while disconnected.

## Approved checks and disruption limits

A signature verifies provenance, not appropriateness for the network. Enable only explicitly reviewed check IDs and pinned revisions, with declared protocols, privileges, expected traffic, timeouts, and negative-evidence semantics. Signature verification and an approved-check manifest are both required for nuclei. Tool updates cannot silently enable new templates or expand behavior.

Initial scanning is bounded discovery and TCP service observation. Default-credential/login attempts, brute force, fuzzing, exploit payloads, state-changing requests, denial-of-service checks, and intrusive scanner scripts are disabled. Later authenticated read-only assessments need an explicit profile and credential policy. A fragile-host policy permits only reviewed discovery/light port checks; the owner may instead exclude a host entirely.

Proposed default traffic ceilings are 50 probes per second per runner and 5 HTTP requests per second per target, at most two active runners, one active job per asset/vantage, and 30 minutes per job. Tool adapters must map and enforce applicable limits or refuse the profile. These are ceilings to test, not guarantees that all devices tolerate them; exclusions and lower overrides remain available. Heavy profiles run only in configured quiet windows. Pause and cancel must stop active network work within 10 seconds on a reachable runner; loss of control connectivity is bounded by local job expiry.

## Identities, authorization, and job signatures

The owner uses a password stored as a salted adaptive hash and a short-lived server-side session over TLS, with secure HTTP-only cookies, CSRF protection, login throttling, and idle expiry. Bootstrap uses a one-time secret accessible only from the deployment host/private path and is disabled after enrollment. Credential recovery is a local administrator operation that revokes existing sessions and is audited. No external identity service is required.

API tokens are random, stored as hashes, shown once, individually revocable, and carry an identity, scope, and expiry. Default maximum lifetime is 90 days, with advance expiry notices and documented overlap rotation. A token scope is supplemented by resource bindings:

- `read`: permitted inventory and evidence reads; never secret material.
- `ingest`: submit supported results only for its enrolled assets/formats; cannot enqueue jobs or claim arbitrary identities.
- `probe`: pull only its assigned jobs, upload only their results, and send its own heartbeat.
- `agent`: read approved context and write its own recommendation artifacts; no decisions, configuration edits, or job execution in v1.
- `admin`: owner-authorized configuration/decision operations, subject to the same scope and scan-safety policy.

Probe jobs are signed envelopes containing job/attempt IDs, probe identity, nonce, targets, allowed profile/image, configuration hash, issued time, and expiry. Reject wrong recipients, stale envelopes, replay, or unknown signing keys. Rotate signing keys with an explicit overlap and revocation process. Tunnel ACLs permit only required probe endpoints, not general LAN access. A compromised probe may falsify its own evidence; label the source and support revocation/quarantine rather than claiming signatures prove truthful observations.

## Isolation and hostile inputs

The internet-facing probe and runners hold no LAN credentials or database credentials. The browser-facing API has no raw container-runtime socket. A small local launcher accepts only approved images, validated job manifests, bounded resources, and an allowlist of capabilities/mounts. It rejects arbitrary commands, privileged containers, and host filesystem mounts. Plugins installed in the core process are trusted administrator-installed code; entry points are not a sandbox.

Default result limits: 50 MiB compressed upload, 250 MiB expanded, bounded nesting/record counts, and a parsing deadline. Reject oversized, truncated, and unsupported results explicitly; stream large inputs and reject archive paths outside the job directory. XML parsing disables DTD/external entity retrieval. Parsers run with no network access and bounded resources. Evidence downloads use safe content types/disposition; inline text is escaped. Limits are configurable through validated deployment settings, with a ceiling enforced before allocation.

## Data handling and AI

Secrets are encrypted in the deployment repository and supplied through restricted files at runtime; no plaintext secrets enter Git, process arguments, logs, or evidence exports. Protect database/raw-output storage with host access controls and encrypted backup storage. Sanitized logs have a shorter retention than finding history. Document host disk-encryption expectations during setup.

Local inference is the default. Hosted use and fallback each require explicit configuration, permitted fields, provider destination, and a spending cap. By default omit raw banners, credentials, private addresses/hostnames, and complete evidence attachments; send only the owner-approved structured context. Strict-privacy mode prohibits hosted fallback. A future pseudonymizer supplements this policy rather than being a prerequisite for basic data minimization. Notifications likewise send minimal summaries with authenticated links, not raw evidence.

Untrusted text remains data with provenance. Validate model output against a schema, cite observations in recommendations, and bound input/output sizes and cost. Quoting alone is not the security boundary: restricted permissions and deterministic decisions remain authoritative. Prompt/model changes require evaluation before release; a failed model does not block detection or manual triage.

## Release and vulnerability handling

Before each scanning milestone ships, demonstrate its scope containment, allowed-check policy, authorization, cancellation, parser limits, and relevant malicious-input fixtures. Pin images/checks, record dependency provenance, review licenses, and document the update process. Keep vulnerable lab targets isolated with no published host ports or LAN/internet route.

For repository vulnerabilities, use GitHub private vulnerability reporting if enabled. Until a private reporting channel is configured, do not post credentials, private network evidence, or exploit details in public issues; report a minimal request for a private contact. Enabling and documenting a private reporting channel is a pre-release task. No response-time commitment is implied for this volunteer project.
