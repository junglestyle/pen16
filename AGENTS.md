# Working on pen15

Build a useful, tunable homelab dashboard with almost no routine operator work. Keep deployment-specific details out of the core. This repository contains designs and branding; implementation has yet to start.

Read the relevant docs before changing behavior:

- [Specification and milestones](docs/SPEC.md)
- [Architecture and data rules](docs/ARCHITECTURE.md)
- [Security and recovery](docs/SECURITY.md)
- [Stack and decisions](docs/stack.md)

Update docs alongside behavior changes. Never commit deployment-specific configuration, credentials, or real network evidence.

## Engineering standards

Use Python 3.12, uv with a committed lockfile, Ruff, strict mypy, and pytest. Keep configuration in pyproject.toml. Expose one command for local and CI checks. Pin runtime/tool images by digest and record tool/parser versions with fixtures.

Keep identity, coverage, findings, intent, and authorization independent of HTTP and scanner processes. Routes call application services shared by the dashboard and API. Use small typed tool/parser/notifier/feed interfaces. Enforce permissions in background paths too.

Use fixed executables, argument arrays, and shell=False. Bound runtime/output and support cancellation. Use transactions for observation, finding, and notification changes. Store UTC timestamps. Migrations preserve evidence.

Log requester, operation, job, outcome, and safe errors. Omit tokens, full request bodies, and raw evidence. Escape untrusted output. Document API permissions in its schema.

Test observable outcomes with sanitized tool fixtures and an isolated listener lab: scope, closed/filtered/unavailable results, identity conflicts, permissions, duplicate/late uploads, cancellation, notifications, and restore. Add advisory and vantage cases with their milestones. Keep the lab disconnected from the real LAN and internet.

Code changes run formatting, lint, typing, relevant tests, and migration checks. Documentation changes check links/assets, numbering, and git diff --check. PRs explain the problem, resulting behavior, and validation. Publish fictional examples and repeatable boundary/recovery demos.
