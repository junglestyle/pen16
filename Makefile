.PHONY: check standards lint test db sync-standards
SHELL := bash
ORG = https://github.com/junglestyle/.github
RAW = https://raw.githubusercontent.com/junglestyle/.github
# Tests drop and recreate the schema, so they get their own database, never PEN15_DATABASE_URL.
TEST_DATABASE_URL = postgresql+psycopg://pen15:pen15@localhost:5432/pen15_test

check: standards lint test

standards:
	@curl -fsSL $(RAW)/main/STANDARDS.md | diff -u - <(tail -n +2 docs/org-standards.md) \
		|| { echo "docs/org-standards.md differs from the org's STANDARDS.md: run make sync-standards"; exit 1; }

lint:
	uv lock --check
	uv run ruff format --check
	uv run ruff check
	uv run mypy

test:
	PEN15_DATABASE_URL=$(TEST_DATABASE_URL) uv run pytest
	PEN15_DATABASE_URL=$(TEST_DATABASE_URL) uv run alembic check

db:
	docker compose -f compose.test.yaml up -d --wait

sync-standards:
	sha=$$(git ls-remote $(ORG) refs/heads/main | cut -f1) && \
	{ echo "<!-- junglestyle/.github STANDARDS.md at $$sha. Change it there, then run make sync-standards. -->"; \
	  curl -fsSL $(RAW)/$$sha/STANDARDS.md; } > docs/org-standards.md
