# Data and execution contracts

These are implementation requirements. [SPEC.md](SPEC.md) owns feature scope; this document defines the rules that prevent incorrect state and misleading results. Persist the versions of these rules so historical results remain interpretable.

## Evidence, coverage, and time

A run records its configuration hash, target manifest, vantage, tool image digest, profile/check-set revision, parser version, requester, request reason, and start/end times. Each attempt has its own identity. An observation is immutable and records the subject, observed time, received time, source attempt, and evidence reference/hash. Corrected parsing creates a new interpretation with provenance rather than rewriting raw evidence.

Coverage is recorded per target/service/check/vantage, including address family. Use explicit outcomes: `detected`, `not_detected`, `unreachable`, `filtered`, `timed_out`, `unsupported`, `parse_failed`, and `cancelled`. Missing output is not `not_detected`. Discovery non-response is not proof that an asset is gone. Keep last-seen history and mark current state unknown/stale after the configured observation window.

A finding can be automatically verified only when the relevant coverage item completed successfully, used a compatible detection method, observed the current asset/service binding from the same vantage, and supplies a supported negative result newer than the last positive result. Each check declares what constitutes negative evidence; an explicitly closed port may resolve a reachability/exposure finding but does not prove that installed software was patched. A successful process exit alone is insufficient.

Partial runs retain useful positive observations. Negative outcomes from an individually complete, validated coverage item may resolve that item only; never extrapolate them to failed or omitted coverage. Changing a profile or removing a check cannot resolve its old findings. Such findings show "Not covered by current profile" until rechecked or explicitly resolved by the owner.

Late data is retained in history but cannot roll current state backward. Compare trustworthy observation ordering, not arrival ordering; reject implausible probe timestamps and flag clock drift. Overlapping contradictory observations remain unresolved until a newer verification establishes order. Re-parsing historical output does not pretend to be a fresh scan or emit current-change alerts automatically.

## Asset and finding identity

An asset has a stable internal ID; addresses are bindings with network/vantage context and first/last observed times. IP reuse alone must not transfer findings or decisions to another device. Explicit operator bindings and authenticated host identities take precedence over inference.

Locally administered MACs are weak identity evidence, not proof of rotation or continuity. A shared hostname or device type is also insufficient. The initial resolver automatically associates only an unambiguous stable identifier with no conflicting evidence; otherwise it proposes a possible match and retains separate assets. Any later heuristic requires documented evidence weights, thresholds, ambiguity fixtures, and recorded confidence. DHCP/mDNS evidence is optional when available, not assumed to be observable from every network.

The owner can merge or split associations with a reason. Preserve original observations and an audit trail, recompute affected views transactionally, and require review of decisions affected by the identity change. Do not silently broaden suppression. Address expiry and asset retirement never delete retained finding history.

A finding fingerprint is `(asset_id, service_key, canonical_check_id, vantage_id)`. `service_key` is protocol/port or an explicit host-level sentinel. Track individual IPv4/IPv6 and address bindings as coverage members; resolve the finding only when every still-applicable member has qualifying negative evidence or an explicitly audited scope/identity decision. Removing an address from scope is not evidence of a fix. Group equivalent findings across vantages for display only; internal results cannot close external findings. Check aliases and changed detection semantics require versioned mapping rules.

## Lifecycle and operator decisions

Store workflow state separately from decision state and resolution reason. A positive observation remains evidence even when accepted or suppressed. The initial workflow supports the following transitions; unsupported transitions return a conflict with no side effect.

| From | To | Actor and required evidence |
| --- | --- | --- |
| No finding | `detected` | Ingester with positive observation and coverage provenance |
| `detected` | `validated` | Approved confirming check or owner with supporting evidence |
| `detected`, `validated` | `triaged` | Owner acknowledgment with recorded actor/time; validation status retained separately |
| Any open state | `remediation_planned` | Owner records intended fix or linked playbook |
| Any open state | `remediated` | Owner records action taken; verification is still pending |
| Any open state | `verified` | Deterministic verifier with qualifying negative coverage and reason `check_passed` |
| Any open state | `verified` | Owner with manual evidence, affected coverage, and reason `manual_verification`; displayed as manually verified |
| Any open exposure finding | `verified` | Activated intent revision covers it; reason `intent_changed`, excluded from fixed-vulnerability metrics |
| `verified` | `detected` | New qualifying positive observation after resolution; emit `regressed`, except an exposure still covered by current intent |
| `verified` | `detected` | Owner reopens with reason, or intent change again makes observed exposure unexpected |

"Any open state" means `detected`, `validated`, `triaged`, `remediation_planned`, or `remediated`. A new compatible positive result refreshes evidence without discarding an ongoing remediation plan. `regressed` is an event, not a second lifecycle system. The AI has no authority for these transitions.

Decisions are `active`, `accepted_risk`, or `false_positive`. Acceptance and false-positive decisions require an owner, reason, exact finding scope, start time, and expiry. Defaults: 30 days for accepted risk, 90 for false positive. They hide repeat notifications only within the recorded scope, never erase evidence, claim a fix, or stop health checks. Expiry restores active review; severity increase, changed check semantics, identity change, or new vantage invalidates the affected suppression and prompts review. Repeated unchanged detections within a valid decision do not repeatedly alert.

Ignoring a host requires a versioned configuration change and records the resulting coverage gap; it cannot silently close findings. Declaring expected exposure follows [the Git workflow](UX.md), with no application-side commits. Every transition/decision includes an actor, timestamp, reason, and evidence/configuration reference in append-only history. Use optimistic revisions for concurrent operator actions.

## Job execution and ingestion

Job states are `queued → leased → running → succeeded | partial | failed | cancelled | skipped`. Every attempt is distinct from the logical job. Scope/profile rejection is recorded before execution; it cannot be reported as a successful empty scan.

- Workers claim with a short transaction and lease, then release database locks before network work. Default lease: 120 seconds, renewed every 30 seconds. An expired lease is eligible for recovery; maximum 3 attempts, bounded by the job deadline.
- Each lease has a monotonically increasing fencing token. Only its current holder can publish authoritative completion. Late results from an old lease are quarantined as historical evidence and cannot change current findings.
- Before replacement, terminate or confirm the old runner stopped. For a disconnected probe, wait for its signed execution deadline and bounded shutdown grace to expire before redispatch. Runner-local deadlines apply even without the server. Never blindly duplicate a potentially active scan.
- Defaults: one active scan per asset/vantage, two runner jobs globally, 30-minute job deadline unless an approved profile declares another bounded limit. Scheduler overlap is coalesced; expired schedules are recorded as missed, not replayed without limit after downtime.
- Cancellation stops new dispatch and terminates the runner with a bounded grace period (10 seconds). Record partial evidence without declaring omitted coverage clean. Global pause uses the same mechanism and needs explicit resume.
- Ingestion identity is `(run_id, attempt_id, output_digest, parser_version)`. A repeated identical submission is a no-op; a conflicting output for the same finalized attempt is rejected and audited. Bind uploads to an authenticated producer and its assigned target manifest.
- Store raw evidence durably before finalizing derived state. Commit normalized observations, coverage, state transitions, diff events, and notification-outbox entries in one transaction. Failed parsing or rollback cannot leave a completed clean run.
- API mutation keys are scoped to identity and operation; reusing a key with different input is a conflict. Retain keys for at least 7 days and expose the resulting resource/status on replay. Browser mutations use equivalent action identifiers.

Reprocessing has a separate explicit operation ID and dry-run summary; it must not accidentally duplicate notifications or reset decision expiry. Deleting expired raw output leaves its hash and provenance and marks re-parsing unavailable.

## Measurement rules

Severity is deterministic with a versioned policy; AI ranking cannot lower it. Initial exposure defaults: internal unexpected service is medium, external unexpected service is high; explicitly labeled sensitive management services are high internally and critical externally. Labels and overrides are versioned and owner-controlled. Scanner-native severity mappings must be documented before enabling each integration. Version-only vulnerability matches remain "potentially affected" until validated; confidence is separate from severity.

Keep per-vantage counts and provide a grouped issue count labeled as such. Display accepted risk, false positives, unsupported/stale coverage, and manual versus automatic resolutions separately. Mean time to remediate runs from first detection to verified resolution, excludes `intent_changed` and false-positive decisions, and reports manual-verification counts. A regression starts a new episode without erasing earlier duration. Suppression does not stop the clock for unresolved issues.

The composite score is deferred to the reporting milestone. Proposed formula: sum active finding weights (critical 10, high 5, medium 2, low 1, informational 0) per finding fingerprint, with separate accepted-risk subtotal. It is an unbounded prioritization index, not a probability or a claim of overall safety. Show raw counts, duplication by vantage, policy version, and freshness next to it. Confirm its usefulness in the pilot before release.

## Required contract fixtures

Exercise a closed port, filtered port, sleeping host, missing check, truncated output, partial parse, IPv4 success with IPv6 failure, internal success with external detection, reused IP, shared hostname, ambiguous MAC change, duplicated upload, expired worker lease, out-of-order result, concurrent operator decision, intent revision change, suppression expiry, and recurrence after verification. Assert final finding state and emitted events, not just parser output.
