.PHONY: check standards lint test db lab image icons sync-standards
SHELL := bash
ORG = https://github.com/lowmagic/.github
# Each test run creates and drops its own database through this localhost admin URL (make db's Postgres).
TEST_ADMIN_URL = postgresql+psycopg://pen16:pen16@localhost:5432/postgres

check: lint test

standards:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	git clone -q --depth 1 --branch main $(ORG) "$$tmp" && \
	"$$tmp/code-standards/sync.sh" check "$$tmp"

lint:
	uv lock --check
	uv sync --frozen
	uv run ruff format --check
	uv run ruff check
	uv run mypy
	{ git ls-files '*.sh'; git ls-files | xargs grep -l '^#!/usr/bin/env bash'; } | sort -u | xargs shellcheck

test:
	PEN16_TEST_ADMIN_URL=$(TEST_ADMIN_URL) uv run pytest -rs

lab:
	lab/egress.sh

image:
	docker build -t pen16:ci .
	docker run --rm --entrypoint nmap pen16:ci --version

# Rerender the app icons in src/pen16/static from docs/assets/pen16-icon-dark.svg; commit what changes.
icons:
	uvx --from resvg-py==0.5.0 python docs/assets/make-icons.py

db:
	docker compose -f compose.test.yaml up -d --wait

sync-standards:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	git clone -q --depth 1 --branch main $(ORG) "$$tmp" && \
	"$$tmp/code-standards/sync.sh" sync "$$tmp" "$$(git -C "$$tmp" rev-parse HEAD)"
