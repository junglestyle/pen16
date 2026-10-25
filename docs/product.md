# Product purpose

## A useful homelab project

pen15 helps one owner see what is exposed, what changed, and which emerging vulnerabilities may affect the systems they run. It should be enjoyable to build, useful from a dashboard, and require almost no routine attention after setup. The owner can tune it as the network and their preferences change.

The project also demonstrates security-aware infrastructure engineering: an explicit threat model, proportionate controls, reproducible deployment, and evidence that failure handling and recovery work. Another engineer should be able to trace a threat to a control, inspect its implementation, and reproduce the demonstration. The scope and accepted risks remain those of a homelab; compliance certification is not a project goal.

## What earns its place

- A dashboard for current exposure, changes, relevant advisories, and monitoring health.
- Scheduled, bounded observations from inside the network and eventually one external vantage.
- Early warning about newly disclosed vulnerabilities and known exploitation, matched to observed or owner-declared software.
- A small API used by both the dashboard and a restricted assistant integration such as Hermes.
- Safe defaults, automatic housekeeping, and tuning without recurring configuration deployments.

Example: a container unexpectedly exposes an admin port. The dashboard shows the change and sends one alert. The owner restricts access, asks Hermes or the dashboard to verify it, and sees the new evidence. Separately, an advisory for software on the NAS produces a source-linked warning even if there is no scanner check for it.

## Threat model and accepted limits

The main concerns are accidental exposure, vulnerable or forgotten services, opportunistic exploitation, and a monitor that silently stops working. Faster exploit development makes timely awareness valuable; pen15 does not promise to discover unknown vulnerabilities or prevent compromise. Feed coverage, inventory quality, scan intervals, and vantage all limit what it can know.

The deployment host and owner are trusted. Runners are constrained to approved networks; remote observations are trusted within their recorded vantage. One probe and pragmatic reachability checks are acceptable for this deployment. A compromise of the host or a lying probe requires investigation and recovery, not a claim that pen15 can independently defeat it.

Detailed controls and accepted risks live in [SECURITY.md](SECURITY.md). A control should address a plausible failure and be cheap enough to sustain. Extra platforms, compliance scanners, scoring systems, and autonomous agents need a demonstrated personal use case before they become project work.

## Success evidence

There is no required weekly review ritual. A stable deployment should run unattended, send useful exceptions, and remain understandable when the owner opens it after time away.

| Outcome | Evidence to collect |
| --- | --- |
| Useful quickly | Set up a fictional 10-asset lab, find an unexpected service, and explain every manual step |
| Low maintenance | Run unattended for four weeks; record interventions and remove recurring chores before adding integrations |
| Useful dashboard and alerts | Seed exposure and advisory changes; show evidence, grouping, and available actions; record nuisance alerts |
| Proportionate security | Demonstrate scope containment, restricted API access, honest incomplete results, and recovery |
| Affordable operation | Measure runtime, memory, and storage on the reference VM; use no required paid service or model |

The reference sizing exercise is up to 100 assets across four networks on a 4 vCPU / 16 GB VM. These are test targets, not capacity guarantees. Publish sanitized configuration, a short demonstration, measurements, and known limitations so another engineer can assess the choices. Keep real infrastructure details and evidence private.
