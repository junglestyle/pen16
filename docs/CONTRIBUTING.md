# Engineering standards

This is a design-stage repository. The commands and tooling below are requirements for the first implementation scaffold, not claims that they exist today. Start with [product purpose](product.md), [the spec](SPEC.md), and [the delivery plan](PLAN.md); read the contracts relevant to the change.

## Development baseline

- Use Python 3.12 initially, declare the supported minor versions in `pyproject.toml`, and test every declared version in CI. Expand support intentionally.
- Use `uv` with a committed lockfile for reproducible development and CI. Do not introduce a second dependency manager.
- Use Ruff for formatting and linting, mypy in strict mode for project code, and pytest. Keep settings in `pyproject.toml`. Document narrow, justified exceptions for third-party interfaces.
- The scaffold must expose one documented local command for the same checks CI runs. Planned underlying checks: `uv lock --check`, `uv run --frozen ruff format --check .`, `uv run --frozen ruff check .`, `uv run --frozen mypy src`, and `uv run --frozen pytest`.
- Container builds pin base/tool images by digest. Record tool and parser versions with fixtures. Include required third-party notices and review redistribution terms before publishing images.

## Code boundaries

Keep domain rules for identity, coverage, findings, and intent independent of HTTP handlers and scanner processes. API routes validate requests and call services; they do not assemble shell commands or implement lifecycle rules inline. Database access and transaction ownership are explicit.

Plugins use versioned contracts and normalized typed models. They may not write core tables directly, bypass scope policy, or import private implementation modules. Validate outputs at the boundary; incompatible plugin versions fail before a job is dispatched. Declare capabilities and supported input versions explicitly.

Prefer small, explicit functions and data models. Type public interfaces and core logic. Use UTC-aware timestamps for storage and display the selected local timezone in the UI. Inject clocks and external services where timing or failures affect behavior. Comments should explain invariants and decisions rather than repeat code.

## Failures, execution, and logs

- Use typed domain errors translated into stable API error codes. Report partial and unavailable results explicitly; never turn an exception into an empty successful result.
- Execute tools with argument arrays, fixed executables, validated options, and `shell=False`. Do not interpolate user targets into commands. Bound execution time, output size, concurrency, and cancellation.
- Make retries bounded and idempotent. Use the lease, attempt, ingestion, and outbox rules in [contracts.md](contracts.md).
- Structured logs include request/job/run IDs, actor, operation, outcome, and safe error code. Never log bearer tokens, secrets, full request bodies, or raw scanner evidence by default. Redact before persistence and notification.
- Apply scope and authorization checks at service boundaries, including background jobs. An authenticated identity is not permission to act on every object.

## API, configuration, and migrations

Use a versioned HTTP API (`/api/v1`) and generate its schema from typed request/response models. Define pagination, size limits, timestamp formats, idempotency keys for mutations, and a stable error envelope. Keep secrets out of URLs. Browser actions use CSRF protection; API credentials remain separately scoped.

Deployment files declare a schema version. Reject unknown fields and incompatible versions with actionable validation errors. Validate and activate a complete revision atomically; retain the last valid configuration on failure.

Every database schema change includes an Alembic migration and an upgrade test from the previous supported release. Document whether rollback is supported; do not assume a destructive downgrade is safe. Preserve retained evidence and document data transformations. Version public plugin, API, and configuration contracts, with migration/deprecation notes before breaking changes.

## Verification and review

Test domain invariants and failure cases rather than implementation details. Required suites grow with the features they protect:

- Unit/fixture tests for parsing, scope decisions, identity ambiguity, per-vantage coverage, lifecycle transitions, and severity floors.
- Database integration tests for duplicate ingestion, concurrent workers, lease expiry, outbox delivery, and migrations.
- Isolated lab tests for the end-to-end operator loop and cancellation/partial failures. Lab networks must be isolated from the host LAN and internet; fixtures contain no private deployment data.
- UI tests for the core decisions, accessible controls, escaped evidence, and stale/failed states.
- Model evaluations only when AI is introduced, including adversarial text and the documented release threshold.

Code PRs require formatting, lint, typing, relevant tests, and applicable migration/lab checks. Documentation PRs require valid local links/assets, a whitespace check, and a consistency review of affected requirements and ADRs. Do not require the scanner lab for prose-only changes. The scaffold adds these gates to CI; none are currently configured.

A PR explains the problem, final behavior, tests/evidence, and material limitations. Link the milestone/requirement and update affected docs in the same change. Changes to safety boundaries, state transitions, or public contracts need explicit reviewer attention. Avoid unrelated refactors and new infrastructure without a demonstrated need.

## Repository hygiene

Keep detailed documentation in `docs/`, the product introduction in root `README.md`, and `AGENTS.md` as a thin guidance index. Keep real configuration, credentials, raw scans, and asset inventories outside the public repository. Use fictional/sanitized fixtures and document how they were produced.

The first scaffold adds `.gitignore`, dependency tooling, CI, example deployment, and a development quickstart. Release notes identify supported versions, migrations, configuration changes, image digests, known limitations, and recovery instructions. Only mark a milestone complete when its evidence exists.
