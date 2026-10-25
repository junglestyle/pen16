# Product purpose

## Who this is for

pen15 is built for the maintainer's homelab and made available for anyone who wants to use it. The primary user is one technically comfortable owner who can administer a Linux VM, Docker, and a private configuration repository.

The owner wants to know what changed, whether it was intended, and whether a fix worked. After setup, pen15 should need a short weekly review and occasional maintenance rather than daily attention. Remediating actual problems can take longer; operating the monitor should not.

## Problem and value

The starting workflow is occasional scanner runs, manually comparing output, and remembering which services were intentionally exposed. This leaves uncertainty about stale results, forgotten exposure, and whether a change actually fixed a finding.

pen15 connects those activities into a repeatable loop: declared scope and intent, scheduled observations, evidence-backed changes, useful notifications, and verification. Scanner integration is a means to that outcome. AI is optional assistance; useful monitoring must work without it.

Example: the owner adds a container to the NAS and accidentally exposes a management port. pen15 reports the new service and its mismatch with declared intent. The owner restricts the listener and requests a verification scan. pen15 resolves the exposure only when the relevant check completes with sufficient evidence, retaining the earlier observation.

## Product boundaries

- One owner and one deployment, initially covering one homelab. Integrations have separate restricted identities.
- Reference acceptance envelope: up to 100 assets across up to 4 configured networks, one internal scanner, and later one external probe. This is a design/test target, not a demonstrated capacity limit.
- First useful release: internal IPv4 discovery and bounded TCP service checks, expected exposure, history, basic triage, one notifier, verification, and health visibility.
- Broader protocol coverage, vulnerability templates, external scanning, compliance, and AI follow as separately accepted milestones in [the delivery plan](PLAN.md).
- No requirement for billing, organizational tenancy, team assignment, enterprise SSO, or hosted infrastructure. Keep extension points without building those products.

## Success criteria

These are proposed acceptance targets to validate during implementation and the maintainer's pilot. Record actual measurements in milestone evidence; revise targets explicitly when evidence warrants it.

| Outcome | Target | Measurement |
| --- | --- | --- |
| First useful result | Within 60 minutes after prerequisites are ready, for a documented 10-asset setup | Time from copying the deployment example to reviewing the first exposure finding; list any manual interventions |
| Low routine effort | At most 15 minutes of review/configuration per week over a 4-week stable-network pilot | Operator diary; report incident remediation and initial setup separately |
| Useful notifications | At least 80% of finding alert groups warrant investigation or an intentional configuration decision | Operator labels over the pilot; fewer than 10 groups is insufficient evidence |
| Predictable health | Stale/failed coverage never renders as a clean scan; whole-server loss is externally detectable | Fault scenarios in the lab plus independent watchdog demonstration |
| Honest verification | No false resolution in the required partial-scan, retry, vantage, and unavailable-host fixtures | Contract tests from [data and execution contracts](contracts.md) |
| Affordable operation | Core fits the reference 4 vCPU / 16 GB VM; no paid services required | Record peak resources and disk growth for the reference workload; optional probe/provider costs reported separately |

Time and cost controls include quiet windows, grouped alerts, bounded scan work, optional heavy scanners, and disabled hosted-model fallback by default. There is no assumed dollar budget: paid providers require an operator-configured cap before use.

## Scope decisions

Prefer changes that reduce operator uncertainty or recurring work. A feature must explain its place in the scan-to-verification loop, its maintenance cost, and how its result is tested. Broad integration coverage does not take priority over reliable core behavior.

The public project documents supported configurations and limitations. The maintainer's private network layout, evidence, and credentials stay in the deployment repository. Reusable defaults and sanitized examples belong here.
