from alembic import command
from alembic.config import Config


def test_migrations_build_the_schema_the_code_declares(engine):
    # Raises if autogenerate would emit anything: a model change with no migration, or a migration that drifted.
    command.check(Config("alembic.ini"))
