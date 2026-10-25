# Operating a low-maintenance deployment

These are planned defaults and release requirements. Executable deployment and recovery commands will be added with the implementation; no working installer is currently shipped.

## Reference deployment and resource envelope

Use one Debian 13 Docker-capable VM with 4 vCPU and 16 GB RAM, PostgreSQL, the core API/UI, and ephemeral runners. Start with a 50 GiB dedicated data allocation and measure actual growth during the pilot. This is a planning baseline, not a measured minimum. Optional local models and Greenbone need separate capacity planning. A remote probe arrives only with external scanning.

Package one core Compose file with opt-in profiles for optional components. Host-specific interfaces and mounts belong in the deployment override. Ansible starts at an existing OS; VM/VPS provisioning remains an operator prerequisite. The first working release documents private TLS access, firewall rules, persistent data paths, and how to reach every configured network. Do not claim coverage for a VLAN without a verified route/interface.

Core operation has no required paid/cloud service. Use an independent self-hosted watchdog on another failure domain if desired. Optional VPS, notification, and hosted-model costs are shown separately; hosted model requests require a configured spend limit and are disabled when the budget is exhausted.

## Schedules, workload, and quiet operation

Initial default is a nightly bounded discovery/TCP profile and a weekly summary. Enable UDP, IPv6, vulnerability templates, compliance, and heavy profiles only when supported and deliberately configured. Record the configured timezone; skip duplicate wall-clock schedule occurrences and record missed occurrences across clock changes. Never start an unbounded catch-up queue after downtime.

Apply the concurrency, traffic, and deadline limits in [contracts.md](contracts.md) and [SECURITY.md](SECURITY.md). Coalesce overlapping jobs for the same asset/vantage. Jobs that cannot run inside their permitted window are recorded as skipped and visible to health monitoring. Pausing scans does not pause health visibility, retention, or credential-expiry reminders.

## Notifications and independent health

- Default finding alerts: high/critical new or escalated findings immediately, grouped by asset/vantage over 5 minutes; lower-severity changes in the weekly digest. Send an immediate event only once per meaningful change; unchanged detections update history.
- Use a durable outbox with event/destination idempotency keys. Retry transient delivery failures with exponential backoff and jitter, starting at 1 minute, capped at 1 hour, for up to 24 hours. Delivery is at least once; destinations without idempotency support can show duplicates. Retain failed deliveries for review and manual replay.
- Show pending/failed deliveries and last successful send. Setup includes a test notification. Daily provider/account credential problems become one continuing health incident rather than a new incident on every retry.
- Default scan health alert: two consecutive missed/failed schedule windows; each schedule declares a deadline and grace period. Default probe heartbeat: every 60 seconds, alert after 5 minutes without one. Show degraded coverage immediately even before the alert threshold.
- The core emits an outbound heartbeat every minute only after checking database access, scheduler progress, and outbox health. An independent watchdog alerts after 5 minutes of missing/unhealthy heartbeats through a channel independent of pen15's notifier path. Its host must survive loss of the pen15 VM; avoiding the same physical host is preferred.
- If the owner declines the independent watchdog, prominently show that whole-server outages cannot be detected by pen15 itself. A green local health screen does not substitute for this check.

Keep schedule failures, stale threat-intelligence feeds, expired credentials, low storage, and provider failures separate from security findings. Maintenance windows can silence external notifications for a bounded duration while retaining the visible condition and audit history. Recovery emits one summary when the condition clears.

## Retention and storage pressure

Proposed defaults: raw output 30 days, normalized observations/diff events and decision history 365 days, operational logs 14 days, successful delivery records 30 days. Keep unresolved findings, current decisions, and minimal supporting evidence/provenance beyond those windows until resolved and the history period elapses. Explain that expired raw output cannot be re-parsed.

Default soft warning is 80% utilization of the data allocation; pause new scans at 90% or less than 5 GiB free, whichever is reached first. Reserve capacity for status/health updates and cleanup. Resume only after storage falls below the warning threshold and the owner acknowledges the pause. Never delete unexpired evidence or unresolved findings merely to make a run succeed. Apply a configurable raw-output budget (20 GiB initially); exhausting it pauses affected collection and alerts rather than reporting an empty result.

Retention jobs run incrementally, record deletion counts, and avoid deleting evidence referenced by active findings or a backup snapshot. The UI exposes retained size, recent growth, oldest available raw evidence, and cleanup failures. Forecast capacity from measured scan sizes; revise defaults if the 100-asset reference workload cannot fit.

## Backup, restore, and upgrades

Target recovery point is 24 hours and target restore time is 2 hours for the reference workload; neither is demonstrated until the release restore exercise passes. Make nightly encrypted backups to storage outside the scanner VM and retain 7 daily and 4 weekly snapshots. The age/decryption key must be recoverable independently of the lost host.

A consistent backup set includes PostgreSQL, all raw files referenced by its snapshot, the active configuration revision, release/image metadata, and a checksummed manifest. Pause ingestion finalization and retention while establishing the database snapshot and raw-file manifest; copy immutable files and keep them pinned until the backup completes. Record success only after validation, and alert on stale/missing backups.

Restore into an isolated replacement: install the pinned release, recover keys/configuration, restore database and evidence, validate references/hashes, and run a read-only health check. Reconcile abandoned leases and disable schedules, notifications, and probe dispatch until the owner explicitly activates the replacement, preventing duplicate scans/alerts. Verify that evidence and decisions survive before reconnecting live targets.

Before an upgrade: review release notes, validate configuration against the new schema, take a verified backup, stop new jobs, drain/cancel running work, and apply migrations once. Then check API/UI, runner readiness, and one lab or explicitly requested bounded verification. Rollback uses the previous image only if schema compatibility is declared; otherwise restore the matching pre-upgrade backup and disclose the resulting data-loss window. Test this recovery path for migrations before release.

## Routine maintenance and failure drills

The weekly digest includes actionable findings, coverage gaps, pending decisions, backup freshness, credential expiry, and available approved updates. Avoid a daily login requirement. Update tool/check images through reviewed release changes; do not automatically enable new scan capabilities.

Before calling a milestone ready, demonstrate server loss, probe loss (when supported), notifier failure, parser failure, disk pressure, failed migration, and restore. Publish expected symptoms, diagnostic locations, and exact recovery commands with the implementation. Track operator effort using [the product targets](product.md), with maintenance and incident remediation reported separately.
