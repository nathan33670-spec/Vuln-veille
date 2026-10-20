"""Helpers for hand-written Alembic migrations."""

from typing import Any

from alembic import op


def execute_script(sql: str) -> None:
    """Runs a multi-statement SQL script (functions, policies) in the migration transaction.

    asyncpg prepared statements accept a single command, so the script goes through the
    driver's simple-query protocol instead.
    """
    connection: Any = op.get_bind().connection

    async def run(driver_connection: Any) -> None:
        await driver_connection.execute(sql)

    connection.run_async(run)
