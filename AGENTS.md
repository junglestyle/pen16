# Working on pen15

Low-touch security dashboard for a homelab and home network.

Read before changing behavior:

- [Specification](docs/SPEC.md): what pen15 does, and its milestones
- [Coding standards](docs/standards.md): how the code should read
- [Architecture](docs/ARCHITECTURE.md): components, API permissions, and data rules
- [Security and recovery](docs/SECURITY.md): scan safety, access, backups, and upgrades
- [Stack and decisions](docs/stack.md): tools and the decisions behind them

Docs live in `docs/` and change with behavior. Never scan anything outside the isolated test lab. Never commit
hostnames, tokens, deployment config, or real network evidence (see [Privacy](docs/standards.md#privacy)).

`make check` runs everything CI runs.
