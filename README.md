<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/pen15-lockup-dark.svg">
    <img src="docs/assets/pen15-lockup-light.svg" alt="pen15" width="200">
  </picture>
</p>

# pen15

**Find the holes before they do.**

Your homelab changes. Containers come and go, devices join the network, and a service you meant to keep private ends up exposed. pen15 is self-hosted attack-surface monitoring designed to tell you what changed, whether it was intended, and whether your fix worked.

The goal is a short, useful review each week, with timely alerts when something needs attention and little maintenance once it's running.

> **In development:** this repository currently contains the design and documentation. There is no runnable release yet. The capabilities below describe what we're building.

## What pen15 will do

- **Catch unexpected exposure.** Compare discovered services with what you intended to make reachable, including services exposed before your first scan.
- **Show what changed.** Keep a history of assets, ports, services, and findings, with evidence behind each change.
- **Check the outside view.** Use a remote probe to see which public services are actually reachable from the internet.
- **Connect new threats to your inventory.** Match vulnerability intelligence to the services you run and perform approved, targeted checks.
- **Verify the fix.** Recheck the relevant service after remediation. Incomplete scans leave the result unresolved, and monitoring failures get their own alerts.

For example: a new NAS container exposes a management port. pen15 flags the unexpected service, shows where it was reachable, and helps you verify that restricting it removed the exposure.

## Built for a homelab

Run it on your own infrastructure and keep your network configuration in a private deployment repo. Core monitoring will work without an LLM or paid cloud service. AI triage and remediation playbooks are optional later additions; you stay in control of decisions and changes to your systems.

The first release focuses on a complete internal monitoring loop: scan, review, declare intent, alert, and verify. External scanning and threat intelligence follow. See the [delivery plan](docs/PLAN.md) for milestones and the [documentation](docs/README.md) for setup assumptions, architecture, and design details.

## Contributing

Start with the [engineering standards](docs/CONTRIBUTING.md) and [specification](docs/SPEC.md). Guidance for coding agents is in [AGENTS.md](AGENTS.md).

Use pen15 only on networks you own or are explicitly authorized to assess. Automated exploitation and autonomous remediation are outside its scope.

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
