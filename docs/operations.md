# Unattended operation

These are planned defaults, to be tuned with actual use. Commands and executable roles arrive with implementation. The goal is automatic operation with useful exceptions, not a recurring maintenance checklist.

## Deployment

Start with an existing Debian 13 VM, Docker Compose, 4 vCPU / 16 GB RAM, and a 50 GiB data allocation. This is a test baseline, not a minimum specification. One API/dashboard service, Postgres, and one serial nmap runner are the core. M3 adds a separate external probe; no local model or vulnerability-scanner fleet is needed.

Ansible owns service startup, host egress rules, runtime secret files, and backup timers. In the reference Tailscale deployment, use Caddy's Tailscale certificate integration for private TLS with automatic renewal; do not rely on manually copied `tailscale cert` files. Keep owner and runner listeners distinct, and health-check certificate expiry. A deployment choosing another private TLS mechanism must supply its own tested renewal/reload path. See [Tailscale's certificate guidance](https://tailscale.com/docs/how-to/set-up-https-certificates).

The owner manages OS security updates through the host's normal update mechanism. Application/tool releases remain pinned and are upgraded deliberately with Ansible; update availability appears on the dashboard. No automatic new checks or privilege expansions accompany an upgrade.

## Default schedule and workload

Run internal discovery and top-1000/declared/observed TCP ports nightly. Aim to complete a rolling full-range sweep every seven days, with bounded chunks and a configurable quiet-window budget. Fragile hosts use their light set only. Sleeping clients can defer work; actual sweep age and unscanned ports remain visible. Routed address ranges consume work even when addresses are unresponsive; do not size them only by discovered assets.

Use one job per runner, a 30-minute job deadline, and the ceilings in [SECURITY.md](SECURITY.md). The initial external profile uses at most 50 probe packets/s and the same chunking/deadlines. Skip work that cannot fit its permitted window and show it as deferred coverage. Prioritize targeted verification and routine scans over background full sweeps, without bypassing quiet windows. Coalesce overlaps and never replay an unlimited backlog after downtime.

At 500 probe packets/s, 65,535 probes alone take at least 131 seconds. Sweeping 100 assets over seven nights therefore needs at least 31 minutes/night, plus routine scans, retransmissions, response waits, and fingerprinting. At 50 packets/s the same single-asset first pass needs about 22 minutes. These lower bounds justify chunking; they are not capacity promises. Measure the configured workload before choosing the sweep interval.

M2 fetches advisories daily with cached results and bounded backoff. The owner can tune cadence and quiet windows in the dashboard within deployment ceilings. Store times in UTC and display the chosen timezone; daylight-saving changes do not trigger duplicate work.

## Notifications and health

Notify on new unexpected exposure, new relevant high/critical or known-exploited advisories, and meaningful escalation. Group related events by asset/vantage over five minutes. Other changes remain on the dashboard or in an optional weekly digest. Accepted-risk/false-positive decisions suppress only their exact scope. No announcement token changes routing.

Start with a short plain-text HTTP POST compatible with ntfy, containing a summary and authenticated dashboard link. The outbox retries transient failures with backoff capped at one hour for up to 24 hours. Preserve failed delivery for review/replay; repeated provider errors become one health incident. At-least-once delivery can produce duplicates.

Show degraded coverage immediately. Default schedule alert is two consecutive missed/failed/partial execution windows; expected sleeping clients are handled separately under [contracts.md](contracts.md). A failed network witness creates one incident immediately. Probe heartbeats are every minute with a five-minute missing threshold. Alert on stale always-on assets, feeds after two missed daily fetches, backups older than two days, credential failures, and expiring certificates. These thresholds are owner-tunable.

Send an optional external-monitor ping every minute while database access, scheduler progress, and notification delivery health pass. An unrecovered permanent delivery error, or pending due deliveries with no progress for five minutes, makes notification health fail. The owner-provided monitor uses its own alert path and should survive scanner-host loss. pen15 ships no watchdog. Local coverage incidents remain distinguishable from total host failure; acknowledge or temporarily mute them without hiding their status. Emit one recovery notice when a condition clears.

## Housekeeping

Default retention: raw evidence 30 days, observations and audit history one year, operational logs 14 days. Preserve unresolved findings, current decisions/settings, and minimal supporting evidence until they are no longer needed. Raw expiry means reparsing is unavailable, not that the observation disappears.

Warn at 80% data-allocation use; pause new collection at 90% or less than 5 GiB free. Cleanup runs automatically and never deletes required evidence to make a scan succeed. Resume resource-paused collection below the warning threshold with at least 5 GiB free. Owner pauses stay paused. Keep the incident history; no acknowledgement is needed for automatic recovery. Show storage growth and backup age on the dashboard.

Optional client housekeeping hides old undeclared entries only when no unresolved findings depend on them. It is inventory cleanup, not remediation. No routine identity-review queue is required.

## Backup, restore, and upgrades

Make nightly encrypted backups to storage outside the scanner VM, retaining seven daily and four weekly copies initially. Pause evidence retention from the start of a PostgreSQL dump until referenced immutable raw files are copied. Include the deployment revision, image versions, and checksummed file list. Raw evidence must be durable before database finalization, so ingestion may continue during the copy. Mark the backup successful only after validating the resulting set. Keep the decryption key independently recoverable and off the scanner host.

The database snapshot contains authoritative settings, intent, decisions, and enrollment records. A settings export is optional; if included, generate it from the same snapshot and label its revision. Do not overwrite restored state with a newer repository export. Re-enroll runners if their credentials changed after the backup. Schedules, notifications, and dispatch stay disabled on a replacement until the owner activates it, preventing duplicate deployments.

Demonstrate an isolated restore with evidence and decisions intact. Record the achieved recovery point/time rather than promising an untested SLA. Before upgrades, take a validated backup, stop new work, drain/cancel active jobs, migrate once, and run health/smoke checks. Test upgrades from a previous supported release when one exists. If schema rollback is unsupported, restore the matching pre-upgrade backup and disclose the lost interval.

A short release record should show the scope, auth, failure, and restore demonstrations plus actual operator interventions. Keep it useful for explaining the engineering, not a compliance paperwork exercise.
