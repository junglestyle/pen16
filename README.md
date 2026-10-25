<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/pen15-lockup-dark.svg">
    <img src="docs/assets/pen15-lockup-light.svg" alt="pen15" width="200">
  </picture>
</p>

# pen15

**Find the holes before they do.**

A security-aware dashboard for your homelab. See what's exposed, what changed, and which emerging vulnerabilities may affect what you run. Set it up, let it monitor, and tune it when you want to.

> **In development:** this repository contains design and documentation. There is no runnable release yet.

## What it will do

- **Show your attack surface.** Browse assets, services, changes, and evidence in one dashboard.
- **Catch unexpected exposure.** Compare reachable services with what you intended, inside the network and from an external probe.
- **Surface relevant threats.** Connect new advisories and known exploitation to your software, with source links.
- **Check your fixes.** Request a bounded verification and see what the scanner actually observed.
- **Work with your assistant.** Give Hermes or another client restricted API access to read status and request approved scans.
- **Stay out of your way.** Run scheduled checks, handle routine housekeeping, and alert on useful changes or monitoring failures.

For example: a new NAS container exposes an admin port. pen15 shows it on the dashboard and alerts you. You restrict access, ask for verification, and review the result. A later advisory for that software can warn you even without an active vulnerability check.

## Built for a homelab

One owner, self-hosted infrastructure, and almost no routine work. Core operation needs no LLM or paid cloud service.

The first release delivers the dashboard and internal monitoring loop. Lightweight vulnerability awareness and the outside view complete v1. See the [specification and milestones](docs/SPEC.md).

## Contributing

Start with [AGENTS.md](AGENTS.md) for engineering standards, [architecture](docs/ARCHITECTURE.md), [security](docs/SECURITY.md), and [stack choices](docs/stack.md).

Use pen15 only on networks you own or are explicitly authorized to assess.

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
