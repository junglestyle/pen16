# Coding standards

pen16 follows the [org standards](org-standards.md) and the org's standards for [Python](org-standards-python.md),
[SQL](org-standards-sql.md), [containers](org-standards-containers.md) and [shell scripts](org-standards-shell.md),
unchanged copies of [junglestyle's](https://github.com/junglestyle/.github/tree/main/code-standards). `.org-standards`
lists the topics it copies beyond the general one. This file adds pen16's own rules and examples. Where it differs from
an org rule, it says so, and it wins.

## Scanning and evidence

- Run fixed executables with argument arrays and `shell=False`. Bound runtime and output, and support cancellation.
- Change observations, findings, and notifications in one transaction. Store UTC timestamps, and compare stored
  times with the database's clock (`func.now()`, `db.now`), never the process's. Migrations preserve evidence.
- Escape untrusted tool and feed output everywhere it's shown.
- Log requester, operation, job, outcome, and safe errors. Never log tokens, full request bodies, or raw evidence.
- Pin runtime and tool images by digest, and record tool and parser versions with their fixtures.

## Dependencies

- Lean on Postgres transactions, Compose restarts, nftables, Tailscale identity, and unattended-upgrades before
  writing your own.

## Structure

- Scope checks and finding closure are critical invariants: one implementation each.
- Routes call application services that the dashboard and API share. Background jobs enforce the same permissions.
- Identity, coverage, findings, intent, and authorization don't know about HTTP or the scanner process. The scanner,
  parser, notifier, and feeds are plain typed functions; one gets a `Protocol` seam when a second implementation of
  it is real.

## Errors and recovery

- Converging state here: closed ports resolve findings, transient faults recover, storage pauses clear.

## Testing

- The behaviors worth a test: scope enforcement, closed/filtered/unavailable results, identity conflicts,
  permissions, duplicate and late uploads, cancellation, notifications, and restore. Advisory and vantage cases
  come with their milestones.
- Tests use sanitized tool fixtures and an isolated listener lab. The lab never touches a real LAN or the internet.

## Running it

- `sudo make lab` proves the runner egress policy in network namespaces. It needs root and nmap, so it runs as its
  own CI job.
- `make image` builds the image and checks that nmap runs in it. It needs Docker and the network, so it's also its
  own CI job.

## Privacy

- Config shape lives in `examples/`: `pen16.toml` for the deployment config, and `pen16.env`, in place of
  `.env.example`, for the environment, with `intake.env` and `listener.env` for the two services that get only
  their own database URL. Deployment config, addresses, and real network evidence live in the private deployment
  repository. Examples and fixtures are fictional.

## Docs

- A slice in the [roadmap](ROADMAP.md) ends with a done-when someone can show on infrastructure they own, with
  fixtures where one exists and the owner's own network otherwise. What it showed is described in roles, and its
  evidence stays out of the repo. The spec keeps the requirement; the roadmap names it.

## Prose

- Name roles, such as the server, the scanner, and the probe.
- Name a specific assistant only as the README's example. The API assumes nothing about who calls it.

## Known deviations

Where pen16 doesn't follow the org standards yet. These are debt to pay down, not overrides: each one should go.

- Config: nothing here sets `PEN16_EVIDENCE_DIR`, `PEN16_RUNNER_TOKEN_FILE`, `PEN16_EGRESS_MARKER`,
  `PEN16_RUNNER_SCOPE`, `PEN16_BACKUP_DIR`, `PEN16_NEIGHBOURS`, `PEN16_COMPLIANCE_CONF` or `PEN16_COMPLIANCE_STATE`, so each always
  takes its default path.
- Docs: [SPEC.md](SPEC.md) opens with what pen16 is, not the problem, its requirements are one flat series
  (`**FR-1**`–`FR-16`) under one heading with no name after each ID, and it has no Unknowns or Open questions
  section.
- Docs: [ROADMAP.md](ROADMAP.md) is arranged by milestones (M1, C1, M2) with a "Shipped" section, and its slices
  have no `Status:` or `Delivers:` line.
- Docs: the shipped slices "Owner dashboard over Tailscale" and "Verified nightly backups" (`ROADMAP.md:24-28`) have
  no done-when.
- Docs: slice C3 (`ROADMAP.md:153`) names no spec requirement, and slice 9 (`ROADMAP.md:109`) names "M1's
  demonstration" instead of the part of FR-11 it delivers.
- Docs: the deferred requirements under the spec's "After the pilot" (`SPEC.md:50`) have no slices; the roadmap's
  "After the pilot" (`ROADMAP.md:207`) holds them back until the pilot has run.
- Python testing: `arf-rhel9-stig.xml` is a real OpenSCAP evaluation of a UBI 9 filesystem, trimmed
  (`conftest.py:22`), not a synthetic fixture.
- Python testing: test files are named one per module (`test_backups.py`, `test_exposure.py`, `test_jobs.py`,
  `test_notify.py` and the rest), not for the behavior they cover.
- SQL: closed sets with no `CHECK`: `findings.kind`, `stig_rules.severity`, and `protocol` and `vantage` in
  `observations`, `findings` and `expected_services`.
