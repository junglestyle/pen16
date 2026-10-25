# Operator experience

## Interface and priorities

Use a small server-rendered application served with the API for setup status, findings, decisions, and verification. Keep the initial frontend to HTML, CSS, and progressive enhancement; a separate SPA is not required. Grafana is optional for later analytical dashboards. Core operator actions must not require Grafana or hand-written API calls.

The home screen answers: is monitoring working, what needs my attention, and what changed? Show coverage freshness before trends or a composite score. Every scan-derived claim links to its evidence and identifies its vantage and observation time.

## Setup to first result

1. The owner copies the example deployment, sets scope, excludes fragile devices, selects a bounded scan profile, and configures one notification destination.
2. `pen15 validate` checks schema, scope conflicts, profile availability, and secret references without scanning. A separate explicit preflight checks database access, runner readiness, routes, and notifier delivery. Failures include a specific corrective action.
3. The owner opens a localhost or private-network bootstrap flow with a one-time secret, creates the owner credential, and invalidates the bootstrap secret. No reusable default password is shipped.
4. Before the first scan, show the target count, addresses, vantage, ports, checks, timing limits, exclusions, and any unsupported coverage. Starting the scan requires an explicit action; installation alone does not scan.
5. Show queued/running/partial/failed/completed status and allow cancellation. An empty inventory before the first successful scan says "No successful scan yet."
6. The first result groups discovered services by asset. The owner reviews a proposed expected-exposure declaration; nothing is implicitly trusted because it appeared in the baseline.

## Declaring intent with Git as the source of truth

The application does not hold Git write credentials. "Declare expected" generates a downloadable patch against the active configuration revision, scoped to the selected asset, protocol, port, and vantage. The owner reviews, commits, and deploys it from the private deployment repository.

Activation validates the entire candidate configuration and atomically records its content hash and optional Git revision. If validation fails, the last valid configuration remains active and the error is visible. A patch based on an old revision must be regenerated or reconciled by the owner; the UI never silently overwrites changes.

The finding remains open with "Configuration change pending" until the matching declaration is activated. Activation resolves the policy violation with reason `intent_changed`; it does not claim the service closed or the vulnerability was fixed. The next scan still measures exposure. The initial release supports stable asset IDs; label selectors and precedence rules can be added after they have a schema and conflict tests.

## Weekly review and finding detail

The default inbox shows new or changed actionable findings, with accepted-risk and false-positive decisions available through filters. Show critical/high changes promptly; group lower-severity changes into the weekly digest by default. Keep monitoring failures in a separate visible group. See [notification behavior](operations.md).

Each finding detail contains:

- A plain-language title and why it needs attention.
- Asset, service, vantage, first/last observation, severity and its deterministic inputs.
- Current workflow status, decision state, detection confidence, and coverage freshness as separate fields.
- Expected versus observed exposure, a bounded escaped evidence excerpt, and the related scan/profile revision.
- Timeline of observations, decisions, configuration changes, remediation claims, and verification.
- Applicable actions: acknowledge, plan remediation, mark remediated, verify now, declare expected, accept risk, or mark false positive.

Example: "NAS management port is unexpectedly reachable from the internal scanner." Show `TCP 8443`, the matched asset, no corresponding declaration, scan time, and a service observation. A failed verification says "Verification incomplete; finding remains open" with the failed coverage item. It does not display a reassuring green state.

Acknowledging records review without changing evidence. Accept-risk and false-positive actions require a reason, precise scope, and expiry; defaults are 30 and 90 days respectively. Renewal is explicit. A changed check, severity increase, or new vantage prompts review. Declaring exposure expected is distinct from accepting a vulnerability risk.

## Remediation and verification

Marking remediated records an operator claim and queues an optional targeted verification; it does not mark the finding verified. Before running, show the same scope/profile summary used for other scans. Verification reports supported resolution, continued detection, or inconclusive coverage. Manual evidence has its own labeled resolution path in [the lifecycle contract](contracts.md).

AI playbooks, when available, are labeled recommendations with source observations and generation time. Detection, decisions, and manual verification work when the model is unavailable. A provider failure shows "AI analysis pending" rather than blocking the inbox.

## Recovery and uncertainty

| Situation | What the operator sees and can do |
| --- | --- |
| No findings, successful coverage | "No findings in the completed coverage" plus coverage details and limitations |
| Offline or sleeping asset | Last seen and unknown current state; no automatic claim that its findings are fixed |
| Partially failed scan | Successful evidence retained, failed coverage highlighted, retry limited to eligible work |
| Offline probe | Last heartbeat, affected schedules, and route/connection diagnostics; other vantages remain usable |
| Ambiguous identity | Proposed match and supporting evidence; confirm association or keep assets separate |
| Alert destination failure | Pending delivery, next retry, last error, and a send-test action |
| Paused scanning | Persistent banner, who paused it, reason, and explicit resume action |
| Old accepted risk | Expiry/review reminder with the current evidence; no silently renewed decision |

## Accessibility and acceptance

Support keyboard-only operation, visible focus, associated labels and errors, readable contrast, and status text in addition to color. Escape untrusted evidence and offer copy/download actions without rendering scanner-provided HTML. Use responsive layouts for desktop and phone; confirmations summarize the actual target and effect.

Milestone demonstrations must walk through setup, baseline review, configuration activation, an unexpected change, a decision, successful verification, and failed verification. Include keyboard navigation, an empty state, and an ambiguous identity. The owner should complete these without editing SQL or composing API requests.
