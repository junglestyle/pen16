# Data and execution contracts

These rules protect the small monitoring loop. [SPEC.md](SPEC.md) defines scope; implementation details that do not change these guarantees can be chosen with the code.

## Evidence and coverage

Each observation records its asset/address binding, protocol/port, vantage, observation time, attempt, tool/profile/parser versions, and evidence digest. Evidence is immutable; corrected parsing adds provenance. Store explicit outcomes: detected, closed, filtered, unavailable, unsupported, failed, or cancelled. Missing output is never a negative result.

Coverage is the scheduled target/address/port manifest, not just the set of responders. L2 discovery requires an interface on the segment. Routed networks use an explicit host list or a bounded address range scanned without ping discovery. A host list deliberately cannot discover devices outside that list. With a routed range, rolling full-range work includes addresses that have never responded; top-1000 non-response alone must not remove an address from discovery.

Nightly scans use TCP top-1000 plus declared and previously observed ports. A rolling full-range sweep targets seven-day freshness for ordinary assets, split into bounded port chunks. This is a tunable goal, not a guarantee: show actual coverage age and outstanding chunks. Fragile hosts use only their explicitly allowed light set. Unavailable targets and disabled families remain visible gaps.

Each network has a configured always-on reachability witness, preferably a host beyond the route being checked. A gateway is allowed but demonstrates only gateway reachability. Check it before negative results from that network are finalized. A failed witness makes the network unverified: retain positives, block automatic resolution and absence-based housekeeping, and raise one health incident. Even a successful witness is not proof that every host is reachable.

A schedule succeeds when its own planned work completes without execution/parser failures and its network witnesses pass. A completed discovery with sleeping clients is successful execution with availability gaps. Failed or omitted required work is partial and counts toward schedule-health thresholds. Keep unavailable always-on assets as separate health incidents; ordinary clients do not create recurring health alarms. Do not use a population-median heuristic in v1.

## Identity and retirement

Declared assets have stable owner-chosen IDs and explicit static-address, MAC, or authenticated-identity bindings. A static address is an owner assertion of continuity; show conflicting evidence instead of silently inheriting another device's decisions. Hostnames and locally administered MACs alone do not establish continuity. Unknown devices remain separate when evidence is ambiguous. Corrections preserve history and invalidate affected decisions.

Mark an unseen asset stale after three completed scheduled discovery runs with a successful network witness. Staleness does not end a binding or resolve a finding. Excluding a target creates a coverage gap, not a fix.

The owner may retire an asset with a reason, resolving its findings as `asset_retired`. Optional client housekeeping hides undeclared assets after 30 days unseen with completed discovery and a working witness, only if they have no unresolved findings. It does not resolve findings. Reappearance restores visibility; a new positive observation reopens a retired finding when still applicable. Thirty days is a configurable clutter-control default, not evidence that a device was decommissioned.

## Findings and decisions

A finding is `open` or `resolved`, keyed by asset, service (or explicit host-level subject), check/advisory identity, and vantage where applicable. Review acknowledgement, notes, decisions, evidence freshness, and confidence are separate fields. No remediation-planning state machine is required.

| Resolution reason | Evidence / authority | Display |
| --- | --- | --- |
| `port_closed` | New compatible closed-port observation for each applicable binding from the same vantage | Port observed closed |
| `exposure_filtered` | Repeated filtering under the rule below | Exposure appears filtered |
| `manual` | Owner reason and optional evidence reference | Resolved by owner |
| `intent_changed` | Explicit matching expected-exposure declaration | Declared expected |
| `asset_retired` | Owner retirement | Asset retired |

For exposure only, a filtered result on a responsive host queues one targeted repeat no sooner than 60 seconds later. Both attempts must show actual host response on the same address/family and vantage (ARP or another port), complete the relevant port check with compatible semantics, and pass the network witness. An assumed-up result from disabled discovery is not host-up evidence. Both results must be newer than the last positive, with no intervening detection or binding/profile change. Two qualifying filtered results may resolve as `exposure_filtered`; a failed or inconclusive repeat leaves it open. Routine schedules may provide the repeat if an immediate one cannot fit the budget.

This is an accepted heuristic for this threat model. Packet loss or selective filtering can still mislead it; it does not prove a firewall rule or patched software. The owner can disable automatic filtered resolution and use manual review. Nmap documents that [filtered results can follow missing responses](https://nmap.org/book/synscan.html). The repeat interval is a tunable operational default, not a statistical confidence guarantee.

Automatic exposure resolution needs qualifying evidence for every still-applicable address/family member. Partial runs can resolve individually complete members but cannot extrapolate to omitted coverage. Internal results cannot close external findings. Later positive evidence reopens the relevant episode unless current intent covers it. Late data cannot reverse newer state; contradictory unordered evidence stays unresolved.

Advisory matches are potentially affected warnings. A closed/filtered port does not resolve them. An owner can resolve with a reason, such as an evidenced upgrade or non-applicability. New material applicability evidence reopens review. Feed disappearance or staleness never resolves a warning.

Severity is deterministic: unexpected internal exposure defaults to medium, public exposure to high, and a small versioned sensitive-service list raises management-service exposure to high internally or critical externally. The owner can override labels. Advisory warnings retain publisher severity and a separate known-exploited flag; unknown severity stays unknown. Product matching uses exact identifiers or explicit aliases, not substring guesses. Known version ranges narrow applicability; missing or ambiguous versions remain potentially affected. Deduplicate by advisory/CVE and affected asset; changed source records update evidence rather than produce a new alert each fetch. Non-CVE watchlist items retain publisher/item identity and are labeled advisory leads rather than confirmed matches.

Accepted risk and false positive suppress repeat notifications only for the recorded finding/evidence scope. Require a reason; an optional review date restores active review when due. Material product/version changes, stronger severity/exploitation evidence, changed identity, or new vantage invalidate the affected decision. A false positive needs no timer. Accepted risks remain visible on the dashboard; no mandatory 180-day renewal cycle is imposed.

## Intent and settings

Expected exposure is keyed by asset/protocol/port/vantage. Bulk declaration applies only to the selected services, never future ports. Record owner, time, reason, and prior/new values. Product-label edits, bindings, decisions, and routine settings have equivalent history and optimistic revisions.

Export one schema-versioned, revisioned bundle containing `assets.yaml`, `exposure.yaml`, and `settings.yaml`, excluding secrets and enrollment credentials. All files come from one database snapshot. Import previews additions, changes, and removals against a current revision, validates references and deployment ceilings, and applies atomically after owner confirmation. Missing files or conflicting revisions fail; removal is never silently inferred from a partial upload. Removed bindings/declarations show their affected findings in the preview.

The database is authoritative after bootstrap. Deployment does not implicitly import exports. Restore uses the database snapshot's settings; newer repository exports require a separate explicit import. Regular Git export is optional and is not the backup mechanism.

## Jobs and notifications

Jobs are queued, running, succeeded, partial, failed, cancelled, or skipped. A run groups bounded discovery/service jobs; large address/port ranges are chunked. Each assignment names its enrolled runner, attempt, targets, profile, configuration revision, and local deadline. Authenticated TLS protects delivery; a runner rejects expired, repeated, wrong-recipient, or locally out-of-scope assignments.

Run one job per runner and at most one per asset/vantage. Use a database transaction to claim work and an attempt generation to reject stale completion. On lost contact, wait for the old attempt's deadline plus shutdown grace before replacing it. Restart discards expired assignments; it never replays a backlog blindly. Retries are bounded to one automatic replacement per job; further failures wait for the next schedule or owner action.

Default job deadline is 30 minutes; split work to fit instead of increasing the deadline silently. Cancel stops dispatch and terminates tool work within 10 seconds on a reachable runner. Local expiry bounds disconnected execution. Manual pause needs explicit resume; transient resource pauses can recover automatically as described in [operations.md](operations.md).

Coalesce equivalent active requests. A `scan` client selects one allowed asset and profile per request, can cancel its own jobs, and cannot bypass quiet windows or global budgets. Default per-client allowance is one outstanding request and six accepted requests per hour, tunable downward or upward by the owner within the deployment budget. These are starting limits for occasional assistant use, not performance targets. API work shares a runner-time budget with schedules so repeated requests cannot monopolize the runner. Request keys make retries idempotent; the API returns the original job or a conflict for changed input.

Store raw files durably before committing observations, state, and outbox events together. Identical attempt/digest uploads are no-ops; conflicting or obsolete attempts cannot finalize state. Notification delivery is at least once with bounded retries, so a receiver may display duplicates. Failed delivery stays visible.

## Demonstrations that matter

Test ordinary closure, repeat filtering, one lost-response attempt, sleeping hosts, broken witnesses, excluded addresses, an uncommon port, ambiguous identity, stale/duplicate uploads, cancellation, restricted API requests, conflicting imports, and restore. M2 adds uncertain and stale advisory fixtures; M3 adds vantage separation and disconnected-probe expiry. Tests should assert dashboard/finding outcomes and emitted alerts, not only parser fields.
