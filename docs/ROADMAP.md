# Roadmap

The order pen16 gets built in. The [spec](SPEC.md) says what it must do; this file says what ships when. Each slice
is usable on its own, names the spec requirements it delivers, says what the owner would notice, and ends with
something someone can demonstrate, on fixtures where they exist and otherwise on their own network. A requirement
that isn't ready yet waits here for its slice rather than becoming a stub in the code.

Three releases: M1 is v0.1, the dashboard and internal monitoring loop. M2 adds advisory awareness and M3 the
outside view; they can ship in either order, and together they complete v1. Nothing after M1 starts until the pilot
has run, and recurring chores it turns up are removed before any integration is added. Host compliance is the
exception: the owner moved it ahead of the pilot, and it runs alongside M1's remaining slices.

## M1: dashboard and internal monitoring (v0.1)

### Shipped

- **Nightly scan from a contained runner.** FR-1 (scope, exclusions, deadlines), FR-2 (routed address lists, gateway
  check), FR-3 (top-1000 TCP plus declared and observed ports, fixed UDP), FR-8. The runner pulls one job at a time
  over an authenticated listener, waits for the host's egress policy, and refuses targets outside its own scope.
  Shown by `sudo make lab` and the job tests.
- **Unexpected exposure becomes a finding and one alert.** FR-5, FR-6, FR-9. Closed ports resolve findings only when
  the gateway answered; a reopened port alerts again; alerts retry with backoff and show their failures. Shown by
  the exposure, job and notification tests.
- **Owner dashboard over Tailscale.** FR-4 (owner-chosen and provisional IDs), FR-7 (expected services, scan now),
  FR-10 (owner identity, runner tokens). Monitoring health, needs attention, exposure, expected services, and
  unnamed devices, with CSRF protection and escaped scan output.
- **Verified nightly backups.** FR-11 in part. Each backup restores into a throwaway database before it counts, and
  a stale backup alerts once.

### 1. Owner decisions

Delivers the rest of FR-6 and FR-7's decisions. You can resolve or reopen a finding by hand, and accept a risk or
mark a false positive for one asset, service and vantage, with a reason. Accepted risks leave "Needs attention" and
get their own list. A material change (new version, new identity, new vantage) brings the decision back for
attention and says why.

Done when: accept the risk on one open port, watch it leave needs attention and stop alerting, change
the service's version in the fixture, and watch it come back with the reason shown.

### 2. Assets, history and recent changes

Delivers the rest of FR-4 and the asset and finding detail from [Dashboard](SPEC.md#dashboard). Each asset has a
page with its bindings, declared and observed services, product labels, and history. A "Recent changes" view lists
new, removed and changed services and versions. You can correct a binding or retire an asset; its history stays,
and a reused address becomes a new provisional device that inherits no decisions.

Done when: rename a device, retire it, hand its address to a new fixture host, and show the old history intact, the
new device unnamed, and nothing expected on it.

### 3. Coverage and rolling sweeps

Delivers the rest of FR-3. The dashboard shows what each scan actually covered, which targets were unavailable, and
how old each network's full-range sweep is. Full-range TCP sweeps run in bounded chunks between nightly scans,
aiming at seven-day freshness. Findings on an unavailable host stay open.

Done when: a host that drops off the network shows as unavailable with its findings still open, and the sweep
age counts down as chunks complete.

### 4. Verification and cancellation

Delivers the rest of FR-1 and FR-7's scan controls. You can request a bounded verification of one asset after a
fix, cancel a running job and see it stop within ten seconds, and mark a host fragile so it only gets the light
port set at the lower ceiling. Expiry stops a disconnected runner on its own.

Done when: cancel a running scan and show nmap gone within ten seconds; scan a fragile host and show only the
light set at the fragile rate in the egress counters.

### 5. Settings in the dashboard

Delivers the rest of FR-7. Schedules, quiet windows, and pauses live in the database and are edited in the
dashboard, within the ceilings the deployment sets. A manual pause waits for you to resume; a resource pause clears
itself. Settings survive a redeploy without a Git change.

Done when: move the nightly window from the dashboard, redeploy, and show it kept; pause and show the next run
held until resumed.

### 6. Restricted API for an assistant

Delivers FR-10. A versioned API with read and scan tokens you create, see once, and revoke; a per-token rate limit
of six scan requests an hour; and a schema that documents each permission. An assistant with read and scan can see
status and ask for an approved scan of a registered asset, and can't touch intent, findings, scope or policy.

Done when: a scripted assistant client requests a scan and reads the result, the seventh request in an hour is
refused, a request to mark a service expected is denied, and a revoked token is refused from the next request.

### 7. Housekeeping and health

Delivers the rest of FR-9 and FR-11's retention. Raw evidence, history, and logs age out on the schedule in
[Backups, housekeeping, and upgrades](SECURITY.md#backups-housekeeping-and-upgrades); findings, decisions and their
evidence don't. Storage warns at 80% and pauses collection at 90%, then resumes on its own. Related alerts group by
asset and vantage over five minutes. An optional external monitor gets a heartbeat while the database, scheduler and
notifications are healthy.

Done when: fill the evidence volume past 90%, show collection paused on the dashboard, free space, and show it
resume with one recovery notice.

### 8. Upgrade and restore drill

Delivers the rest of FR-11. An upgrade is a pin bump and a playbook run that validates a backup, drains jobs,
migrates once, and checks health, with the matching backup restored on failure. A restore onto a replacement host
comes up with schedules, notifications and dispatch disabled until you enable them, and runners re-enroll when
credentials differ.

Done when: upgrade from the previous tagged release and show the dashboard unchanged; restore last night's
backup onto a clean host and show evidence and settings intact with nothing dispatched.

### 9. Pilot

Delivers M1's demonstration. Run the [M1 demo](#m1-demo) end to end, then run unattended for four weeks on the
owner's own network, recording setup effort, resource use, nuisance alerts, and every intervention. Chores that
recur get removed before M2 or M3 starts.

Done when: four weeks have passed with every intervention explained and the tally written up, without real network
evidence, in the deployment repository.

### M1 demo

1. Bring up the private dashboard against a fictional or owned network.
2. Scan and inspect discovered services.
3. Bulk-declare selected services expected.
4. Open an unexpected port.
5. Receive one alert, close the port, and verify resolution.

Also show scope containment, filtered and unavailable results staying open, cancellation and deadlines, denied
assistant actions, notification failure, and restored evidence and settings.

## Compliance

### C1. Compliance results on the dashboard

Delivers FR-14, FR-15 and FR-16. A host's weekly OpenSCAP result arrives at the intake with its own token. The
dashboard shows each host's benchmark, profile, content version and pass rate, its failing rules by severity with
STIG IDs, waivers with reasons, and hosts that have stopped reporting. The first result and every pass-to-fail
regression alert once. Each result offers its STIG Viewer checklist and its remediation playbook.

Done when: the RHEL 9 STIG fixture shows a pass rate and failing rules; a second upload where one rule regresses
alerts with that rule; waiving it leaves it listed as failing with the reason, and the checklist shows the reason
and the vulnerability shared by two rules as open.

### C2. Hosts report on their own

Delivers the deployment half of FR-14. The deployment installs OpenSCAP, the pinned content, the host's profile,
its tailoring file and its token, and enables the weekly timer. Tailoring records every deselected rule and changed
value with a reason, and a small custom benchmark, composed into its own data stream, checks what the upstream
content doesn't, such as container runtime and tailnet settings. The owner fetches a host's playbook, runs it in
check mode, applies it, and the next result shows the fix.

Done when: two of the owner's hosts report on schedule; one fix applied from the generated playbook shows as a
pass the following week.

### C3. pen16 on a STIG-hardened host

pen16's own host moves to an operating system with a DISA STIG profile and evaluates itself against it. Rules the
container runtime, SELinux, FIPS mode or application whitelisting can't meet are tailored out with a justification
each, which the checklist carries as comments.

Done when: pen16 runs on the hardened host with backups and scans unchanged, and its own checklist shows every open
vulnerability either fixed or justified.

## M2: advisory awareness

### 10. Advisory feeds

Delivers the fetching half of FR-12. KEV and the selected advisory sources are fetched daily, with NVD enrichment
when configured. The dashboard shows each source's freshness, and feed health degrades after two missed fetches.
Feeds never start a scan or resolve a finding.

Done when: the dashboard shows fresh sources after a fetch from fixtures, and a source held back for two days shows
degraded with one alert.

### 11. Relevant advisories

Delivers the matching half of FR-12 and the "Relevant advisories" view. Explicit product identifiers, aliases and
versions match against observed services; the view shows potentially affected assets, the match reason, source
links, unmatched services, and non-CVE watchlist items. Relevant high or critical and known-exploited issues alert.
Resolving an advisory finding is your decision.

Done when: the relevant, unrelated, ambiguous, stale and duplicate fixtures each produce the outcome their name
says, and only the relevant one alerts.

### 12. Trends

Delivers the "Trends" view. Open findings and time to resolve, over the pilot's history.

Done when: the view draws the pilot's four weeks from the database alone.

## M3: the outside view

### 13. External probe

Delivers FR-13's vantage. A probe host with its own internet egress runs the same runner against the approved public
targets as its own identity and vantage. Tunnel ACLs allow it only the runner listener. Internal and external
evidence stay separate, and an internal closed port never resolves an external finding.

Done when: the probe finds a port the internal runner sees closed, and the external finding stays open.

### 14. Probe safety and heartbeat

Delivers the rest of FR-13. Before each job the probe checks its own egress, the path to the target, and DDNS against
the home WAN, and stops on any failure. It heartbeats every minute, and five minutes of silence alerts.

Done when: cut the probe's network and get the alert inside five minutes; point DDNS elsewhere and show the probe
refuse to work.

## After the pilot

Each item under [After the pilot](SPEC.md#after-the-pilot) becomes its own slice here once the pilot says which
chores recur and which integrations earn their keep. Until then they're deferred requirements, not work in progress.
