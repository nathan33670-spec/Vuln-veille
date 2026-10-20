"""Alembic environment: migrations run as the ``vv_migrator`` role."""

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from app.core.db import Base, to_async_dsn
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _dsn() -> str:
    dsn = os.environ.get("VV_DATABASE_URL_MIGRATOR")
    if not dsn:
        raise RuntimeError("VV_DATABASE_URL_MIGRATOR is required to run migrations")
    return to_async_dsn(dsn)


def run_migrations_offline() -> None:
    context.configure(url=_dsn(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def _do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = create_async_engine(_dsn())
    async with engine.connect() as connection:
        await connection.run_sync(_do_run_migrations)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
