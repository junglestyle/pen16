"""Database roles for the two services other machines reach: the runner listener and the compliance intake. Each
logs in as its own role with only the table privileges its requests use, so a flaw in parsing a runner's or a
host's upload can't read secrets or rewrite intent through the database. The dashboard and the worker keep the
owner role that runs the migrations.

`pen16 migrate` brings the roles up to date after each upgrade, so a new table is granted in the same change that
adds it. The tests run the listener and the intake as these roles, so a missing grant fails them.
"""

import os

from psycopg import sql
from sqlalchemy import Connection, text

# Role, the environment variable holding its password, and the privileges it gets on each table. An insert needs
# SELECT as well as INSERT: SQLAlchemy returns the new row's key.
ROLES: dict[str, tuple[str, dict[str, str]]] = {
    "pen16_listener": (
        "PEN16_LISTENER_DB_PASSWORD",
        {
            "tokens": "SELECT, UPDATE (last_used_at)",
            "jobs": "SELECT, UPDATE",
            "assets": "SELECT, INSERT",
            "bindings": "SELECT, INSERT, UPDATE",
            "binding_events": "SELECT, INSERT",
            "observations": "SELECT, INSERT",
            "expected_services": "SELECT",
            "findings": "SELECT, INSERT, UPDATE",
            "finding_events": "SELECT, INSERT",
            "decisions": "SELECT, UPDATE (withdrawn_at, withdrawal)",
            "mac_sightings": "SELECT, INSERT",
            "notifications": "SELECT, INSERT",
            "incidents": "SELECT, INSERT, UPDATE",
        },
    ),
    "pen16_intake": (
        "PEN16_INTAKE_DB_PASSWORD",
        {
            "tokens": "SELECT, UPDATE (last_used_at)",
            "assets": "SELECT, INSERT",
            "compliance_scans": "SELECT, INSERT",
            "compliance_rules": "SELECT, INSERT, UPDATE",
            "compliance_results": "SELECT, INSERT",
            "compliance_waivers": "SELECT",
            "notifications": "SELECT, INSERT",
            "incidents": "SELECT, INSERT, UPDATE",
        },
    ),
}


def ensure(conn: Connection) -> None:
    """Create or update each role with its password from the environment, and reset its grants to exactly
    ROLES's, in the caller's transaction."""
    driver = conn.connection.driver_connection
    if driver is None:
        raise RuntimeError("no database connection to set roles up on")
    for role, (variable, grants) in ROLES.items():
        password = os.environ.get(variable)
        if not password:
            raise SystemExit(f"{variable} is not set (see examples/pen16.env)")
        exists = conn.scalar(text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role})
        driver.execute(
            sql.SQL("{} ROLE {} LOGIN PASSWORD {}").format(
                sql.SQL("ALTER" if exists else "CREATE"), sql.Identifier(role), sql.Literal(password)
            )
        )
        driver.execute(
            sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(sql.Identifier(role))
        )
        for table, privileges in grants.items():
            # The privilege lists are this file's own, not input.
            driver.execute(
                sql.SQL("GRANT {} ON {} TO {}").format(
                    sql.SQL(privileges), sql.Identifier(table), sql.Identifier(role)
                )
            )
