# Coding standards

pen15 follows the [org standards](org-standards.md) and the org's [Python standards](org-standards-python.md),
unchanged copies of [junglestyle's](https://github.com/junglestyle/.github/tree/main/code-standards). `.org-standards`
lists the topics it copies beyond the general one. This file adds pen15's own rules and examples. Where it differs
from an org rule, it says so, and it wins.

## Jungle Style

- Lean on Postgres transactions, Compose restarts, nftables, Tailscale identity, and unattended-upgrades before
  writing your own.

## DRY

- Scope checks and finding closure are critical invariants: one implementation each.

## YAGNI

- A deferred requirement gets a line in [After the pilot](SPEC.md#after-the-pilot).

## Zen

- Routes call application services that the dashboard and API share. Background jobs enforce the same permissions.

## Wu wei

- Converging state here: closed ports resolve findings, transient faults recover, storage pauses clear.

## Pragmatic Programmer

- Orthogonality: identity, coverage, findings, intent, and authorization don't know about HTTP or the scanner
  process. The scanner, parser, notifier, and feeds sit behind small typed interfaces.

## Scanning and evidence

- Run fixed executables with argument arrays and `shell=False`. Bound runtime and output, and support cancellation.
- Change observations, findings, and notifications in one transaction. Store UTC timestamps. Migrations preserve
  evidence.
- Escape untrusted tool and feed output everywhere it's shown.
- Log requester, operation, job, outcome, and safe errors. Never log tokens, full request bodies, or raw evidence.
- Pin runtime and tool images by digest, and record tool and parser versions with their fixtures.

## Testing

- The behaviors worth a test: scope enforcement, closed/filtered/unavailable results, identity conflicts,
  permissions, duplicate and late uploads, cancellation, notifications, and restore. Advisory and vantage cases
  come with their milestones.
- Tests use sanitized tool fixtures and an isolated listener lab. The lab never touches a real LAN or the internet.

## Running it

- `make check` runs everything CI runs except the org standards check.
- `make standards` checks [org-standards.md](org-standards.md) and each topic's copy against the org's current
  files, so a hand edit, a stale copy, or a copy whose topic isn't in `.org-standards` fails. It needs the network,
  so it isn't part of `make check`; CI runs it as its own job. `make sync-standards` refreshes the copies; to follow
  another topic, add it to `.org-standards` and run it.
- `sudo make lab` proves the runner egress policy in network namespaces. It needs root and nmap, so it runs as its
  own CI job.
- Doc changes also check links, FR/ADR numbering, and `git diff --check`.

## Privacy

- Overrides the org rule's `.env.example`: deployment config, addresses, and real network evidence live in the
  private deployment repository. Examples and fixtures are fictional.

## Prose

- Name roles, such as the server, the scanner, and the probe.
- Name a specific assistant only as the README's example. The API assumes nothing about who calls it.

## Known deviations

Where pen15 doesn't follow the [Python standards](org-standards-python.md) yet. These are debt to pay down, not
overrides: each one should go.

- SQLAlchemy and alembic have no ADR in [stack.md](stack.md): ADR-002 picks Postgres, but not the ORM or the
  migration tool. With that ADR, the ORM and `NNN_name.sql` rules are met.
- Tooling: it builds with `uv_build`, not hatchling, and mypy checks `tests` too.
- The `Dockerfile` installs uv with `pip`.
- Typing: the four `# type: ignore[type-arg]` in `jobs.py` don't say why they're safe.
- `web.py` loads its templates from `Path(__file__).parent`, not `importlib.resources`.
