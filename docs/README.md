# pen15 documentation

> **Status:** design phase. This repository contains documentation and branding assets. There is no runnable application, installer, test suite, or CI yet. Features and commands below are planned.

pen15 is a personal attack-surface dashboard with unattended scans, relevant vulnerability awareness, and a restricted API for integrations such as Hermes. It demonstrates security-aware infrastructure through proportionate controls, reproducible deployment, and recovery evidence. It should be useful and fun without becoming a maintenance job.

## Planned delivery

M1/v0.1 delivers the dashboard, internal IPv4/TCP monitoring, intent, bounded API scans, alerts, and recovery. M2 adds lightweight advisory matching; M3 adds one external vantage. M2 and M3 can follow M1 in either order and together complete v1. Approved API remediation is a future use case with separate authorization. See [PLAN.md](PLAN.md).

## Prerequisites

The owner can administer a Linux VM, Docker, and a private deployment repository. The reference is Debian 13, 4 vCPU / 16 GB RAM, and an initial 50 GiB data allocation. Ansible configures an existing host. Setup needs authorized network access, a private TLS path, notification destination, encrypted secrets, and backup storage. An optional external monitor detects whole-host loss; M3 needs a separate internet vantage. These are planning assumptions, not demonstrated capacity claims.

After setup, current intent and routine settings live in the dashboard/database. Export to Git is optional. No model or paid service is required for core operation; optional probe/provider costs are recorded separately.

## Documentation

| Read | Purpose |
| --- | --- |
| [Product purpose](product.md) | Personal utility, threat model, engineering demonstration, accepted limits |
| [Dashboard experience](UX.md) | Views, setup, tuning, verification, and quiet failure handling |
| [Specification](SPEC.md) | Retained and retired requirements |
| [Delivery plan](PLAN.md) | Small increments and evidence of completion |
| [Engineering standards](CONTRIBUTING.md) | Code boundaries and relevant checks |
| [Architecture](ARCHITECTURE.md) | Components, API capabilities, deployment/state ownership |
| [Contracts](contracts.md) | Evidence, findings, jobs, decisions, and imports |
| [Security](SECURITY.md) | Trust boundaries, controls, and accepted risks |
| [Operations](operations.md) | Automatic housekeeping, notifications, backup, restore, upgrades |
| [Decisions](stack.md) | Current stack and the supersession ledger |

Documentation changes check local links/assets and `git diff --check`. Implementation will add executable checks in M0. Keep real configuration, credentials, and network evidence private. Use pen15 only on systems you own or are authorized to assess.
