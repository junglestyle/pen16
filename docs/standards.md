# Coding standards

pen16 follows the [org standards](org-standards.md) and the org's standards for [Python](org-standards-python.md),
[SQL](org-standards-sql.md), [containers](org-standards-containers.md) and [shell scripts](org-standards-shell.md),
unchanged copies of [junglestyle's](https://github.com/junglestyle/.github/tree/main/code-standards). `.org-standards`
lists the topics it copies beyond the general one. This file adds pen16's own rules and examples. Where it differs from
an org rule, it says so, and it wins.

## Scanning and evidence

- Run fixed executables with argument arrays and `shell=False`. Bound runtime and output, and support cancellation.
- Change observations, findings, and notifications in one transaction. Store UTC timestamps. Migrations preserve
  evidence.
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
  parser, notifier, and feeds sit behind small typed interfaces.

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
- Doc changes also check links, FR/ADR numbering, and `git diff --check`.

## Privacy

- Config shape lives in `examples/`. Deployment config, addresses, and real network evidence live in the private
  deployment repository. Examples and fixtures are fictional.

## Docs

- A deferred requirement stays in the [spec](SPEC.md) and gets a later slice in the roadmap, which for now is
  [After the pilot](SPEC.md#after-the-pilot) (see Known deviations).

## Prose

- Name roles, such as the server, the scanner, and the probe.
- Name a specific assistant only as the README's example. The API assumes nothing about who calls it.

## Known deviations

Where pen16 doesn't follow the org standards yet. These are debt to pay down, not overrides: each one should go.

- SQLAlchemy and alembic have no ADR in [stack.md](stack.md): ADR-002 picks Postgres, but not the ORM or the
  migration tool. With that ADR, the ORM and `NNN_name.sql` rules are met.
- Tooling: it builds with `uv_build`, not hatchling, and mypy checks `tests` too.
- The `Dockerfile` installs uv with `pip`.
- Typing: the four `# type: ignore[type-arg]` in `jobs.py` don't say why they're safe.
- `web.py` loads its templates from `Path(__file__).parent`, not `importlib.resources`.
- Dependencies: FastAPI has no ADR in [stack.md](stack.md), only a row in its table.
- Structure: `tokens.revoke` has no caller.
- Privacy: `examples/` has no env file. `db.py` and `worker.py` read `PEN16_DATABASE_URL`, `PEN16_NTFY_URL` and
  `PEN16_NTFY_TOKEN`, and no example or doc names them.
- SQL: surrogate keys are `BIGSERIAL`, SQLAlchemy's default for a `BigInteger` primary key, not identity columns.
- Data modeling: statuses and kinds are literals with a `CHECK`, not `StrEnum`s.
- Testing: the code doesn't refuse a non-local test database, and the test fixture downgrades whatever
  `PEN16_DATABASE_URL` names.
- Errors: a missing `PEN16_DATABASE_URL` raises `RuntimeError`, not `SystemExit`.
- Dependencies: no dependency has a lower bound.
- Running it: CI's `image` job isn't in `make check`, and nothing here says so.
- Containers: `worker` and `runner` don't handle SIGTERM and don't run with `init: true`.
- Containers: `deploy/compose.yaml` sets no `logging:`.
- Shell: `make check` doesn't run shellcheck, which reports two findings in `lab/egress.sh:63`; `deploy/pen16-egress`
  has no `.sh` name, so a `'*.sh'` glob would miss it.
- Docs: the build order is the [spec](SPEC.md)'s [Milestones](SPEC.md#milestones) and
  [After the pilot](SPEC.md#after-the-pilot), not slices in a `docs/ROADMAP.md`.
