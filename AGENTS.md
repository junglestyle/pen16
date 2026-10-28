# Working on pen16

Low-touch security dashboard for a homelab and home network.

Read before changing behavior:

- [Specification](docs/SPEC.md): what pen16 does
- [Roadmap](docs/ROADMAP.md): the order it gets built in
- [Coding standards](docs/standards.md): how the code should read, on top of the org's [principles](https://github.com/junglestyle/.github/blob/main/PRINCIPLES.md) and standards (`docs/org-standards*.md`)
- [Architecture](docs/ARCHITECTURE.md): components, API permissions, and data rules
- [Security and recovery](docs/SECURITY.md): scan safety, access, backups, and upgrades
- [Stack and decisions](docs/stack.md): tools and the decisions behind them

Docs live in `docs/` and change with behavior. Never scan anything outside the isolated test lab. Never commit
hostnames, tokens, deployment config, or real network evidence (see [Privacy](docs/standards.md#privacy)).

Run `make check` before committing. It runs everything CI runs, except the org standards check (`make standards`, needs the network) and
the runner egress lab: `sudo make lab` (needs nmap).
