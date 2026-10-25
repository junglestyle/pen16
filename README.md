<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/pen15-lockup-dark.svg">
    <img src="docs/assets/pen15-lockup-light.svg" alt="pen15" width="200">
  </picture>
</p>

# pen15

**Find the holes before they do.**

A security dashboard for your homelab and home network. See what’s exposed, what changed, and which new vulnerabilities may affect what you run. Set it up, let it monitor, tune it when you want.

> **In development:** M0 records an nmap XML scan and reports unexpected exposure. There is no scanner, dashboard, or release yet.

## What it will do

- **Show your attack surface.** Browse assets, services, changes, and evidence in one dashboard.
- **Catch unexpected exposure.** Compare reachable services with what you intended, inside the network and from an external probe.
- **Surface relevant threats.** Connect new advisories and known exploitation to your software, with source links.
- **Check your fixes.** Request a bounded verification and see what the scanner actually observed.
- **Work with your assistant.** Give an assistant such as Hermes restricted API access to read status and request approved scans.
- **Stay out of your way.** Run scheduled checks, handle routine housekeeping, and alert on useful changes or monitoring failures.

For example: a new container on your server exposes an admin port. pen15 shows it on the dashboard and alerts you. You restrict access, ask for verification, and review the result. A later advisory for that software can warn you even without an active vulnerability check.

## Built for a homelab

One owner, self-hosted infrastructure, and almost no routine work. Core operation needs no LLM or paid cloud service.

The first release delivers the dashboard and internal monitoring loop. Lightweight vulnerability awareness and the outside view complete v1. See the [specification and milestones](docs/SPEC.md).

## Running it

You need [uv](https://docs.astral.sh/uv/) and Docker.

```sh
make db      # throwaway Postgres for the checks
make check   # everything CI runs
```

Against your own database, `PEN15_DATABASE_URL=... uv run alembic upgrade head`, then
`uv run pen15 ingest scan.xml` records an internal nmap XML scan and prints each unexpected open port.

## Contributing

Start with [AGENTS.md](AGENTS.md) and the [coding standards](docs/standards.md).

Use pen15 only on networks you own or are explicitly authorized to assess.

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
