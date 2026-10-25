# Security and recovery

| Threat or failure | Control | Evidence |
| --- | --- | --- |
| Accidental exposure | Compare observations with intent; alert on changes | Unexpected listener demo |
| Vulnerable software | Daily advisories and product matches | Relevant/unrelated advisory fixtures |
| Harmful or escaped scan | Fixed profiles, exclusions, deadlines, host egress rules | Raw-packet scope and cancellation tests |
| Stolen API token | Resource permissions, separate runner listener, tunnel ACLs | Denied owner/cross-runner actions |
| Hostile evidence | Bounded parsing, escaped UI, fixed commands | Malformed-output fixtures |
| Silent failure or lost state | Health alerts, delivery retries, encrypted backups | Failure and restore demos |

## Scan safety

Canonicalize targets, bound expansion, resolve at dispatch, and pin approved addresses. Use fixed executables and argument arrays without a shell, scripts, redirects, or arbitrary options. Bound runtime, memory, and output.

The runner has only NET_RAW, without database credentials or a runtime socket. Other containers drop capabilities. Before dispatch, Ansible installs default-deny nftables netdev egress on every runner interface, including after recreation. Permit authorized targets and named API/DNS dependencies; deny exclusions, database, owner API, metadata, and unsupported traffic. Test raw-packet enforcement and startup without policy.

Exclude prohibits directed probes, including ARP requests. Fragile permits only an explicit light port set without version probing or full sweeps. Initial ceilings are 500 probe packets/s internally and 50 for fragile/external targets. Bound fingerprinting connections separately.

M3 uses a dedicated runner listener. Tunnel ACLs allow only that listener, without subnet routes or an exit node. Before jobs, check independent public egress, target path, and DDNS against the home WAN; stop external work on failure.

## Access and secrets

Serve private TLS with automatic certificate renewal. Owner authentication uses an adaptive password hash, expiring server-side sessions, secure cookies, CSRF protection, and login throttling. Bootstrap uses a one-time private secret; local recovery revokes sessions.

API tokens are random, hashed, shown once, and individually revocable. Store runner tokens in restricted files. Replace compromised credentials and re-enroll affected runners.

Disable parser external resources and XML entities; escape output and generate storage paths. Limit uploads to 50 MiB compressed/250 MiB expanded; bound feed downloads. Treat scan/feed prose as data, including in Hermes.

Keep sops/age secrets in the private deployment repository. Decrypt on the Ansible controller; keep the age key off the scanner host. Restrict runtime files and omit credentials/raw evidence from logs and alerts.

## Backups, housekeeping, and upgrades

Make nightly encrypted off-host backups, keeping seven daily and four weekly copies. Pause evidence retention during database/file copying; validate checksums and referenced files before marking success. Keep the recovery key independently recoverable. Alert when backups exceed two days old.

Restore in isolation and demonstrate evidence/settings intact. Keep schedules, notifications, and dispatch disabled on a replacement until activated. Re-enroll runners when restored credentials differ.

Delete raw evidence after 30 days, observations/audit history after one year, and logs after 14 days; preserve unresolved findings, decisions, settings, and supporting evidence. Warn at 80% storage; pause collection at 90% or below 5 GiB free. Clean automatically and resume below 80% with 5 GiB free.

Automate host security updates and pinned application/tool upgrades through Ansible. Validate a backup, drain jobs, migrate once, and run health checks. On failure, restore the matching backup. Test parser fixtures and upgrades from the previous supported release.
