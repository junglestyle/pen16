# Threat model and controls

This is a design to implement and demonstrate. The deployment protects a personal homelab and shows proportionate infrastructure engineering. It is not a compliance baseline or a guarantee against every adversary.

## Threats worth addressing

| Threat or failure | Control | Evidence |
| --- | --- | --- |
| An accidental service or public forward exposes something private | Compare observations with explicit intent; alert on new unexpected exposure | Seed an unexpected listener and inspect its evidence |
| An emerging disclosure affects software the owner runs | Daily advisories, product/watchlist matches, freshness and uncertainty | Seed relevant, unrelated, and incomplete advisories |
| A scan damages a fragile device or escapes authorized scope | Fixed light profiles, exclusions, deadlines, host-owned egress policy | Raw-packet scope test, fragile-profile test, cancellation |
| A stolen assistant/probe token gains owner authority | Resource-scoped API tokens, dedicated runner listener, tunnel ACLs | Negative authorization and cross-runner tests |
| Hostile evidence or feed content exploits parsing or steers an assistant | Bounded local parsing with external resource loading disabled, escaped UI, no arbitrary commands or decision authority for scan clients | Malformed-output and denied-action fixtures |
| Monitoring stops, notifications fail, or state is lost | Separate health status, outbox retries, optional external monitor, automated backups | Failure notification and isolated restore demo |

The host administrator and deployment repository are trusted. Full host compromise is outside containment. A remote probe can falsify its own observations; one trusted vantage is an accepted cost/complexity tradeoff. Network observations cannot establish universal reachability, a patched host, or absence of unknown vulnerabilities. Document blind spots rather than adding machinery to imply certainty.

## Safe scanning and egress

Canonicalize targets, bound expansions, resolve addresses at planning/dispatch, and pin the job to the approved addresses. Keep the intended DNS name when needed. Disable redirects, scripts, discovered-link crawling, arbitrary scanner arguments, and external callbacks. New active checks need their own bounded profile before use.

The internal runner has only `NET_RAW`; all other added/default capabilities are dropped. It has no database credentials or runtime socket. Other application containers drop all capabilities. Fixed executables receive argument arrays with no shell. Each tool subprocess gets bounded time, memory, and output. Long-lived runner compromise can persist across jobs within its allowed network; this is accepted, and recovery replaces the container and revokes its token.

Ansible-managed host startup installs default-deny nftables netdev egress policy on every runner interface in the runner's network namespace before enabling job execution, including after recreation. It allows declared target networks minus exclusions, plus named infrastructure dependencies such as the runner API and DNS. Explicit denies for the database, owner API, and host metadata take precedence over broad target-network allows. Dependencies and reachability witnesses must be explicitly authorized; conflicting exclusions fail validation. IPv4, IPv6, and ARP require explicit treatment; unsupported traffic is denied. The runner cannot administer its firewall.

Scope or ceiling changes stop affected work, apply policy through the host deployment role, and reopen dispatch only after readiness checks pass. Failure leaves scanning stopped and visible. Do not build a new privileged runtime daemon for this. The lab must test raw packet senders, including queue bypass, and restart with policy absent. [nftables documents the netdev hook](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks); [Linux 6.12's packet path](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/packet/af_packet.c) includes the direct-egress check. Actual deployment behavior still needs the lab proof.

`exclude` means no probes directed at the host, including ARP target requests. Shared-segment broadcasts for other destinations can still reach it. `fragile` means only the explicit light port set, with no service-version probing or full sweep by default. Ordinary service detection also excludes intrusive scripts and unsafe tool defaults; validate chosen options against the pinned tool.

Initial scan ceilings to tune in the lab are 500 probe packets/s for the serial internal runner and 50 for fragile targets. These are maxima, not expected speeds or guarantees of device tolerance. Bound service-fingerprinting connections separately in the profile; scanner port-scan rate flags alone are not a total-traffic limiter. Prefer one job at a time to rate sharing. Full sweeps are chunked and their actual freshness is shown. Lower rates, smaller port sets, and longer sweep intervals are supported.

## Owner and integration access

The dashboard/API is private, served over TLS. The owner uses a salted adaptive password hash and an expiring server-side session with secure cookies, CSRF protection, and login throttling. Bootstrap has a one-time local/private secret. Local administrator recovery revokes sessions. No external identity platform is required.

API credentials are random, stored as hashes server-side, individually revocable, and shown once. Tokens have optional expiry; there is no mandatory calendar rotation or self-rotation protocol in v1. Store runner tokens in restricted persistent files, not images. Replace them on suspicion of compromise or re-enrollment. Restore may require re-enrollment if credentials changed after the backup; show that mismatch instead of silently broadening access.

| Permission | Authority |
| --- | --- |
| `read` | Read permitted inventory, findings, jobs, and sanitized evidence; no secrets |
| `scan` | Request approved scans/verification for bound assets and profiles; inspect/cancel its own requests |
| `runner` | Pull only assigned jobs, upload their results, and report its own heartbeat |

An assistant receives only the required read/scan bindings. It cannot edit intent, acknowledge/accept/resolve findings, change safety ceilings, or run remediation. Owner session authorization remains distinct. Shared budgets, coalescing, and per-client request limits apply to API work. Scan output and advisory prose are untrusted data even when returned to Hermes; the API does not accept instructions embedded in them.

## External probe

Serve runner routes on a dedicated listener with no owner routes. The deployment's tailnet policy permits the probe only that host/port; it is an explicit prerequisite, not something two failed connection attempts can prove. Configure no exit node and no accepted subnet routes. Demonstrate restrictive policy before enrollment.

Before each job, check enabled families' public egress addresses against the home WAN, validate the actual target path avoids the tunnel, and compare DDNS. Tests run in the actual scan path; container routes alone may not describe host forwarding. If the supported topology cannot establish that path, skip the job and show why. Heartbeats report these results. Optional forbidden-canary tests are diagnostics, with unreachable and indeterminate distinguished; they do not replace ACL enforcement.

A failed self-test stops external work, not the internal runner. Loss of control connectivity is bounded by the assignment deadline. A compromised probe's results can be quarantined and its token revoked; authenticated transport does not prove truthful evidence.

## Evidence and secrets

Parse locally with external resource loading disabled, disable XML DTD/external entities, escape displayed text, generate storage paths, and reject oversized/truncated inputs explicitly. Initial limits are 50 MiB compressed and 250 MiB expanded per upload; smaller profile limits are allowed. Feed downloads have size/time limits and only use owner-configured sources; reject redirects outside the configured source policy. The core's feed/notifier egress is separate from scanner target scope.

Secrets stay encrypted with sops/age in the deployment repository and are decrypted on the Ansible controller. Send only the runtime files each service needs, with restricted permissions and secret-safe Ansible logging. The age key stays off the scanner host. Backups encrypt to an independently recoverable recipient. [Ansible's SOPS lookup](https://docs.ansible.com/projects/ansible/latest/collections/community/sops/sops_lookup.html) runs on the controller.

Logs, notifications, and settings exports omit credentials and unnecessary raw evidence. Assistant reads are an intentional disclosure to the configured assistant: scope them accordingly. A future hosted-model integration would need explicit destination/data policy; no hosted inference is built into v1.

## Release discipline

Pin images and tool versions, test relevant parser fixtures on upgrades, and keep lab targets isolated from the real LAN and internet. Publish supported configurations and the small set of boundary/recovery demonstrations. Document a private vulnerability-reporting channel before a public release. Controls should be supported by evidence; residual risks should be explicit and appropriate to this deployment.
