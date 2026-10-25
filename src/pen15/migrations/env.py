from alembic import context

from pen15.db import connect, metadata

with connect().connect() as connection:
    context.configure(connection=connection, target_metadata=metadata)
    with context.begin_transaction():
        context.run_migrations()
