# Dashboard and operator experience

The dashboard is the main way to use pen15. It should be useful when opened out of curiosity, after an alert, or after weeks away. No weekly review, inbox-zero workflow, or Grafana installation is required.

## Home dashboard

| View | What it answers |
| --- | --- |
| Monitoring health | Are scans, feeds, notifications, backups, and the external probe working? When did they last succeed? |
| Exposure | What is reachable internally and externally, and which services are unexpected? |
| Recent changes | What appeared, disappeared, changed version, or changed reachability? |
| Relevant advisories | What newly disclosed or known-exploited issues may affect my software, and why? |
| Needs attention | Which open findings need a decision? Accepted risks and false positives remain available separately. |

Keep the first screen compact. Link each count to its underlying assets or findings. Show observation time, vantage, and coverage next to conclusions. Health is independent of finding counts: zero findings with stale scans never gets a reassuring all-clear. Advisories arrive in M2 and the external view in M3; unfinished features are not empty successful panels.

Asset detail shows declared/observed services, address bindings, product/version labels and provenance, last-seen time, port coverage, full-sweep age, and history. Finding detail shows why it exists, its evidence, any decision, and the resolution reason. Avoid a composite score.

## Setup once

1. Copy the fictional deployment, declare authorized networks and discovery methods, a reachability witness per network, exclusions/fragile hosts, and safety ceilings. Configure a notifier, backup destination, and optional external-monitor URL.
2. Validate offline, then run explicit preflight for interfaces/routes, firewall readiness, database, private TLS, and test notification.
3. Use the one-time bootstrap flow to create the owner login. Review target/port counts and start the first scan explicitly; installation alone does not scan.
4. Inspect discovered services and bulk-declare only the selected ones expected. Give important assets stable IDs. Start the default schedule.
5. Optionally create a restricted read/scan token for Hermes, selecting assets, profiles, and request limits. The token preview states what it can and cannot change.

An unscanned installation says “No successful scan yet.” First-run findings need no individual ceremony: bulk actions operate on the displayed selection, with a preview and one confirmation.

## Tune as needed

The owner can adjust scan cadence, quiet windows, rolling sweep interval, notification thresholds/grouping, optional digest, expected exposure, product labels/watchlist, and precise accepted-risk or false-positive decisions. Show the effective setting and its coverage/noise consequence before applying. Changes take effect without a restart and remain inside deployment safety ceilings. Network scope, credentials, and host policy remain deployment operations.

No decision expires merely to generate routine work. An optional review date is available; material evidence changes bring a decision back for attention. Unchanged detections update history without repeated alerts. Operational faults form one continuing incident with recovery notice.

The database holds current intent/settings. Export is an optional complete revisioned bundle for portability or Git; import shows a diff and requires explicit confirmation. The owner does not have to keep the repository synchronized for monitoring or backup to work.

## Investigate and verify

From a finding, inspect evidence, declare selected exposure expected, accept risk, mark false positive, request verification, or resolve manually with a reason. Retirement is an asset action. Acknowledgement records review without pretending to fix anything. Do not require tickets, remediation plans, or evidence uploads.

Verification shows “Port observed closed,” “Exposure appears filtered,” “Still detected,” or “Inconclusive.” Filtered resolution uses the repeat-check rule in [contracts.md](contracts.md) and is labeled as a heuristic. Unavailable hosts and failed scans leave findings unresolved. The owner can disable that heuristic. Advisory resolution remains an owner decision in v1; port closure does not claim a software patch.

Hermes can answer questions from permitted API data, request an approved scan/verification, and report the job outcome. It cannot acknowledge, suppress, resolve, or declare intent. The API returns the same evidence and uncertainty shown in the dashboard. Future remediation will need a separate owner-approved action flow.

## Quiet failure handling

| Situation | Dashboard and behavior |
| --- | --- |
| Sleeping client | Last seen and unavailable coverage; no repeated health alarm or inferred fix |
| Failed network witness | Network unverified, affected resolutions paused, one health incident |
| Failed job/parser | Successful evidence retained, failed coverage visible, bounded retry |
| Stale advisory feed | Last good fetch remains visible; no “unaffected” conclusion |
| Notifier failure | Pending/failed delivery, retry status, and send-test control |
| Disk pressure | Collection paused; automatic recovery after cleanup reaches the safe threshold |
| Owner pause | Visible reason and explicit resume control |
| No external monitor | Whole-host loss cannot be detected locally; the blind spot stays visible |

Use readable text, keyboard navigation, visible focus, labeled inputs, escaped evidence, and layouts that work on a phone. Core demonstrations should be possible through the dashboard or documented restricted API without SQL or hand-built HTTP requests.
