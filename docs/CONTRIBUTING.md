# Engineering standards

This is a design-stage repository. Planned commands are not available yet. Read [product.md](product.md), [PLAN.md](PLAN.md), and the contracts relevant to a change. Optimize for a useful dashboard, unattended operation, and controls proportionate to the homelab threat model.

## Baseline

Use Python 3.12 initially, `uv` with a committed lockfile, Ruff, strict mypy for project code, and pytest. Declare/test supported versions. Keep settings in `pyproject.toml` and expose one local command for the same checks CI runs. Pin runtime/tool images by digest and record tool/parser versions with fixtures. Review redistribution terms before publishing images.

## Boundaries

Keep identity, coverage, findings, intent, and authorization independent of HTTP and scanner processes. Routes validate and call application services; they do not assemble shell commands. The dashboard and restricted API use the same rules. Use small typed internal tool/parser/notifier/feed interfaces; there is no public plugin compatibility promise.

Use fixed executables, argument arrays, and `shell=False`. Validate options, bound runtime/output, and implement cancellation. Apply scope and resource permissions in service/background paths, not only routes. No API accepts an arbitrary command or scanner option string.

Use explicit transactions for observation/state/outbox changes and idempotent attempt handling. Store UTC timestamps and inject clocks/external services where useful for testing. Configuration/export schemas are versioned; reject unknown/incompatible fields and retain the previous valid state after failure. Migrations preserve evidence. Test upgrades from prior releases when they exist; do not build a rollback framework before there is one.

Log requester, operation, job/attempt, outcome, and safe error codes. Do not log tokens, full request bodies, or raw evidence by default. Escape untrusted output. Keep API errors useful without exposing secrets. Generate an API schema with documented read/scan permissions so a client such as Hermes can operate within explicit limits.

## Evidence and checks

Tests should protect observable behavior: scope enforcement, filtered/unavailable results, identity conflicts, permissions, duplicate/late results, notifications, and restore. Use sanitized real-tool fixtures and a small lab with common/uncommon listeners and filtering. The lab has no path to the real LAN or internet. Add advisory/vantage cases when their milestones arrive.

Code changes run formatting, lint, typing, relevant tests, and migration checks where applicable. Use keyboard-usable dashboard controls and explicit empty/stale/error states. No model evaluation suite, intentionally vulnerable application fleet, or generalized plugin harness is needed for v1.

Documentation changes validate local links/assets, pass `git diff --check`, and reconcile requirements, milestones, and ADRs. The first scaffold will automate these checks. No scanner run is required for prose-only changes.

A PR explains the problem, resulting behavior, relevant evidence, and accepted limitations. Keep real network configuration, credentials, and evidence out of the public repository. Publish fictional examples and repeatable boundary/recovery demos. Keep [AGENTS.md](../AGENTS.md) short; detailed guidance belongs here and in the relevant design document.
