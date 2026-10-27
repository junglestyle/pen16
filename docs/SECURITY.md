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

The runner has only NET_RAW, without database credentials or a runtime socket. Other containers drop capabilities. Before the runner takes a job, the host loads default-deny nftables netdev egress on its only interface, again after every restart, and the runner waits for the host's stamp on its current namespace. Permit authorized targets and named API/DNS dependencies; deny exclusions, database, owner API, metadata, and unsupported traffic. Test raw-packet enforcement and startup without policy.

Exclude prohibits directed probes, including ARP requests. Fragile permits only an explicit light port set without version probing or full sweeps. Initial ceilings are 500 probe packets/s internally and 50 for fragile/external targets. Bound fingerprinting connections separately.

M3 uses a dedicated runner listener. Tunnel ACLs allow only that listener, without subnet routes or an exit node. Before jobs, check independent public egress, target path, and DDNS against the home WAN; stop external work on failure.

## Access and secrets

Serve the dashboard only over Tailscale, with automatic certificate renewal. The owner is identified by Tailscale identity headers and an allowed login; pen16 stores no passwords. Reject identity headers that don't come from the local proxy, and use CSRF protection on state-changing forms.

API tokens are random, hashed, shown once, and individually revocable. Store runner tokens in restricted files. Replace compromised credentials and re-enroll affected runners.

Disable parser external resources and XML entities; escape output and generate storage paths. Limit uploads to 50 MiB compressed/250 MiB expanded; bound feed downloads. Treat scan/feed prose as data, including in assistant clients.

Keep sops/age secrets in the private deployment repository. Decrypt on the Ansible controller; keep the age key off the scanner host. Restrict runtime files and omit credentials/raw evidence from logs and alerts.

## Backups, housekeeping, and upgrades

Make nightly off-host backups, keeping seven daily and four weekly copies. [pen16-backup](../deploy/pen16-backup) restores each dump into a throwaway database with no network, checks its schema version and that every evidence file it references is in the archive, and checks the off-host copy against its checksums before recording success. Backups aren't encrypted: they go to storage that already holds the host's own disk, and a plain file is one the nightly check can test. Encrypt them before they leave the owner's network. Pause evidence retention during copying. Alert when backups exceed two days old.

Restore in isolation and demonstrate evidence/settings intact. Keep schedules, notifications, and dispatch disabled on a replacement until activated. Re-enroll runners when restored credentials differ.

Delete raw evidence after 30 days, observations/audit history after one year, and logs after 14 days; preserve unresolved findings, decisions, settings, and supporting evidence. Warn at 80% storage; pause collection at 90% or below 5 GiB free. Clean automatically and resume below 80% with 5 GiB free.

Host security updates run automatically with Debian's unattended-upgrades. Application and tool upgrades are deliberate: bump the pin and run the playbook. Renovate can optionally open the bump PR. Validate a backup, drain jobs, migrate once, and run health checks. On failure, restore the matching backup. Test parser fixtures and upgrades from the previous supported release.
