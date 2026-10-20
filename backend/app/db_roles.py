"""Provisioning of the least-privileged PostgreSQL roles (SECURITY.md §4.10).

- ``vv_migrator`` owns the schema and runs migrations (DDL);
- ``vv_app`` and ``vv_worker`` get DML on tables created by the migrator;
- ``vv_portal`` gets nothing by default: each portal view is granted explicitly.

None of them is superuser or has BYPASSRLS. Run once with an administrator
connection (``python -m app.cli provision-db-roles``); safe to re-run.
"""

from dataclasses import dataclass

import asyncpg

MIGRATOR = "vv_migrator"
APP = "vv_app"
WORKER = "vv_worker"
PORTAL = "vv_portal"
ROLES = (MIGRATOR, APP, WORKER, PORTAL)
MIN_PASSWORD_LENGTH = 24


@dataclass(frozen=True)
class RolePasswords:
    migrator: str
    app: str
    worker: str
    portal: str

    def for_role(self, role: str) -> str:
        return {MIGRATOR: self.migrator, APP: self.app, WORKER: self.worker, PORTAL: self.portal}[
            role
        ]


async def _execute_formatted(conn: asyncpg.Connection, template: str, *args: str) -> None:
    """Builds DDL with PostgreSQL's ``format()`` so identifiers and literals are quoted safely."""
    statement: str = await conn.fetchval(
        "SELECT format($1, " + ", ".join(f"${i + 2}::text" for i in range(len(args))) + ")",
        template,
        *args,
    )
    await conn.execute(statement)


async def provision_roles(
    conn: asyncpg.Connection, database: str, passwords: RolePasswords
) -> None:
    for role in ROLES:
        password = passwords.for_role(role)
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(
                f"password for {role} must be at least {MIN_PASSWORD_LENGTH} characters"
            )
        exists = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", role)
        verb = "ALTER" if exists else "CREATE"
        await _execute_formatted(
            conn,
            verb + " ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS "
            "NOREPLICATION PASSWORD %L",
            role,
            password,
        )

    await _execute_formatted(conn, "REVOKE ALL ON DATABASE %I FROM PUBLIC", database)
    for role in ROLES:
        await _execute_formatted(conn, "GRANT CONNECT ON DATABASE %I TO %I", database, role)
    await _execute_formatted(
        conn, "GRANT CREATE, TEMPORARY ON DATABASE %I TO %I", database, MIGRATOR
    )

    await conn.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
    await _execute_formatted(conn, "ALTER SCHEMA public OWNER TO %I", MIGRATOR)
    for role in (APP, WORKER, PORTAL):
        await _execute_formatted(conn, "GRANT USAGE ON SCHEMA public TO %I", role)

    for role in (APP, WORKER):
        await _execute_formatted(
            conn,
            "ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public "
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I",
            MIGRATOR,
            role,
        )
        await _execute_formatted(
            conn,
            "ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public "
            "GRANT USAGE, SELECT ON SEQUENCES TO %I",
            MIGRATOR,
            role,
        )
