"""Identity columns instead of serials"""

from alembic import op

revision = "0005"
down_revision = "0004"

TABLES = ["observations", "findings", "jobs", "notifications", "backups", "compliance_scans"]


def _run(statement: str, table: str) -> None:
    op.execute(statement.format(table=table))  # the table names are this file's own, not input


def upgrade() -> None:
    for table in TABLES:
        _run("ALTER TABLE {table} ALTER COLUMN id DROP DEFAULT", table)
        _run("DROP SEQUENCE {table}_id_seq", table)
        _run("ALTER TABLE {table} ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY", table)
        _run(
            "SELECT setval(pg_get_serial_sequence('{table}', 'id'), coalesce(max(id), 0) + 1, false) FROM {table}",
            table,
        )


def downgrade() -> None:
    for table in TABLES:
        _run("ALTER TABLE {table} ALTER COLUMN id DROP IDENTITY", table)
        _run("CREATE SEQUENCE {table}_id_seq OWNED BY {table}.id", table)
        _run("ALTER TABLE {table} ALTER COLUMN id SET DEFAULT nextval('{table}_id_seq')", table)
        _run("SELECT setval('{table}_id_seq', coalesce(max(id), 0) + 1, false) FROM {table}", table)
