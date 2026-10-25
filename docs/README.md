# pen15 documentation

See the [project README](../README.md) for the product introduction. This directory contains requirements, design decisions, contributor guidance, and the implementation plan.

> **Status:** design phase. This repository contains documentation and branding assets. There is no runnable application, installer, test suite, or CI yet. Features and commands described in the design are planned, not available capabilities.

## Planned release scope

The first useful release covers internal IPv4/TCP scanning, declared exposure, history, a small operator UI, basic triage, one notification destination, verification, and monitoring health. IPv6/UDP, vulnerability templates, external probes, and structured threat intelligence build toward v1. Compliance integrations, AI playbooks, and analytical dashboards are optional later increments. See the [delivery plan](PLAN.md) for dependencies and demonstrations.

## Intended operator and prerequisites

The owner is comfortable administering a Linux VM, Docker, and a private Git repository. The planned reference host is Debian 13 with 4 vCPU and 16 GB RAM; 50 GiB of data storage is a starting planning allocation, not a measured minimum. Ansible configures an existing host. Private TLS access, routes/interfaces to the chosen networks, encrypted configuration secrets, and backup storage are setup prerequisites. External scanning later needs a separate probe with an internet vantage.

No paid service or model is required for core monitoring. Optional probes, heavy scanners, and hosted AI have separate resource/cost implications. Coverage limits and incomplete observations must always be visible; pen15 is not proof that a network is free of vulnerabilities.

## Documentation

| Read | For |
| --- | --- |
| [Product purpose](product.md) | Homelab audience, low-maintenance goals, and proposed success measures |
| [Operator experience](UX.md) | Setup, weekly review, decisions, Git-managed intent, and recovery states |
| [Specification](SPEC.md) | Functional requirements and scope |
| [Delivery plan](PLAN.md) | First release, dependencies, acceptance demonstrations, and deferrals |
| [Engineering standards](CONTRIBUTING.md) | Code boundaries, tooling, review gates, and contribution workflow |
| [Architecture](ARCHITECTURE.md) | Components, interfaces, and deployment layout |
| [Data and execution contracts](contracts.md) | Coverage, identity, findings, retries, and evidence semantics |
| [Security design](SECURITY.md) | Threat boundaries, scope containment, credentials, and data handling |
| [Operations](operations.md) | Health, alerts, retention, backups, upgrades, and maintenance |
| [Stack decisions](stack.md) | Technology choices and their tradeoffs |

## Development

Start with [AGENTS.md](../AGENTS.md) and the [engineering standards](CONTRIBUTING.md). M0 will add the package, lockfile, local checks, CI, lab harness, and fictional deployment example. Until then, documentation changes should validate local links/assets and pass `git diff --check`; there is no application command to run. Keep real homelab configuration and scan evidence out of this public repository.

## Responsible use

pen15 is for assessing networks and systems you own or are explicitly authorized to test. The design requires every scan and its network traffic to stay within the operator's scope policy, with approved bounded checks. Automated exploitation and autonomous remediation are excluded. See the [security design](SECURITY.md) for the required controls and release gates.

## License

Apache-2.0. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
