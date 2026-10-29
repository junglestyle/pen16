#!/usr/bin/env bash
# Tests this checkout's migrations against a copy of real data before a deploy runs them: restores a nightly
# pen16.dump into a throwaway Postgres, upgrades it to head, checks nothing was lost, then downgrades to where it
# started and upgrades again. Run it from the checkout you're about to deploy:
#   deploy/test-migration.sh <pen16.dump>
# Needs podman (or docker) and uv. It never touches the live database, and removes its container on exit. Safe to
# re-run. The dump is real data: delete your copy afterwards.
set -euo pipefail

[[ $# == 1 ]] || { echo "usage: $0 <pen16.dump>" >&2; exit 2; }
dump=$(realpath "$1")
repo=$(cd "$(dirname "$0")/.." && pwd)
engine=$(command -v podman || command -v docker)
image=$(sed -n 's/^ *image: *\(postgres[^ ]*\).*/\1/p' "$repo/deploy/compose.yaml" | head -1)   # production's
[[ -n $image ]] || { echo "no postgres image in deploy/compose.yaml" >&2; exit 1; }
name=pen16-migration-test
port=55433
url=postgresql+psycopg://pen16:test@127.0.0.1:$port/pen16
tables=(observations findings jobs notifications backups compliance_scans)   # 0005's identity columns

trap '"$engine" rm -f "$name" >/dev/null 2>&1 || true' EXIT
sql() { "$engine" exec -i "$name" psql -U pen16 -d pen16 -v ON_ERROR_STOP=1 -tAc "$1"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
# Row counts of the tables that existed before the upgrade: tables a migration adds start empty and are checked apart.
counts() {
    local t
    for t in $existing; do echo "$t $(sql "SELECT count(*) FROM $t")"; done
}
migrate() { (cd "$repo" && PEN16_DATABASE_URL=$url uv run --frozen alembic "$@"); }

"$engine" run -d --name "$name" -e POSTGRES_USER=pen16 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=pen16 \
    -p "127.0.0.1:$port:5432" "$image" >/dev/null
# Over TCP: the image's first-start server listens only on its socket.
for _ in $(seq 60); do "$engine" exec "$name" pg_isready -h 127.0.0.1 -U pen16 -q && break; sleep 1; done
"$engine" exec -i "$name" pg_restore -U pen16 -d pen16 --no-owner --exit-on-error < "$dump"

start=$(sql 'SELECT version_num FROM alembic_version')
echo "restored at revision $start"
existing=$(sql "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1")
before=$(counts)
declare -A max
for t in "${tables[@]}"; do
    max[$t]=0
    if [[ -n $(sql "SELECT to_regclass('$t')") ]]; then max[$t]=$(sql "SELECT coalesce(max(id), 0) FROM $t"); fi
done

migrate upgrade head
head=$(sql 'SELECT version_num FROM alembic_version')
echo "upgraded to revision $head"
[[ $(counts) == "$before" ]] || fail "row counts changed"
for t in $(sql "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1"); do
    grep -qx "$t" <<<"$existing" && continue
    [[ $(sql "SELECT count(*) FROM $t") == 0 ]] || fail "new table $t isn't empty"
    echo "  $t: new, empty"
done
for t in "${tables[@]}"; do
    [[ $(sql "SELECT attidentity FROM pg_attribute WHERE attrelid = '$t'::regclass AND attname = 'id'") == a ]] \
        || fail "$t.id isn't GENERATED ALWAYS AS IDENTITY"
    # The next id must clear every existing one, or the next insert collides.
    seq=$(sql "SELECT pg_get_serial_sequence('$t', 'id')")
    next=$(sql "SELECT CASE WHEN is_called THEN last_value + 1 ELSE last_value END FROM $seq")
    (( next > max[$t] )) || fail "$t's next id $next doesn't clear its max ${max[$t]}"
    echo "  $t: identity, next id $next, max ${max[$t]}"
done
# Each CHECK the migrations built matches the code's StrEnum, as tests/test_closed_sets.py asserts on a test
# database. Read-only: the test's own fixtures would wipe this one.
(cd "$repo" && PEN16_DATABASE_URL=$url uv run --frozen python - <<'EOF'
import re
from sqlalchemy import text
from pen16 import db
from tests.test_closed_sets import CLOSED_SETS
with db.connect().connect() as conn:
    for constraint, names in CLOSED_SETS:
        found = conn.scalar(text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :n"),
                            {"n": constraint})
        assert found and set(re.findall(r"'([^']*)'", found)) == {str(n) for n in names}, constraint
print(f"  {len(CLOSED_SETS)} CHECKs match their StrEnums")
EOF
) || fail "a CHECK doesn't match its StrEnum"

migrate downgrade "$start"
[[ $(sql 'SELECT version_num FROM alembic_version') == "$start" ]] || fail "downgrade didn't return to $start"
[[ $(counts) == "$before" ]] || fail "row counts changed on downgrade to $start"
migrate upgrade head
[[ $(counts) == "$before" ]] || fail "row counts changed on the second upgrade"
echo "PASS: $start to $head and back: $(wc -l <<<"$before") existing tables' row counts unchanged throughout"
