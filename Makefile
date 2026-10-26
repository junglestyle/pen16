.PHONY: check standards lint test db lab sync-standards
SHELL := bash
ORG = https://github.com/junglestyle/.github
# Tests drop and recreate the schema, so they get their own database, never PEN15_DATABASE_URL.
TEST_DATABASE_URL = postgresql+psycopg://pen15:pen15@localhost:5432/pen15_test

check: lint test

standards:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	git clone -q --depth 1 --branch main $(ORG) "$$tmp" && \
	"$$tmp/code-standards/sync.sh" check "$$tmp"

lint:
	uv lock --check
	uv run ruff format --check
	uv run ruff check
	uv run mypy

test:
	PEN15_DATABASE_URL=$(TEST_DATABASE_URL) uv run pytest
	PEN15_DATABASE_URL=$(TEST_DATABASE_URL) uv run alembic check

lab:
	lab/egress.sh

db:
	docker compose -f compose.test.yaml up -d --wait

sync-standards:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	git clone -q --depth 1 --branch main $(ORG) "$$tmp" && \
	"$$tmp/code-standards/sync.sh" sync "$$tmp" "$$(git -C "$$tmp" rev-parse HEAD)"
