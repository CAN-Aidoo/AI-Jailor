"""Alembic migration environment."""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from aijailer.db.base import Base

# Import all models so they are registered with Base.metadata
from aijailer.models.tenant import Tenant, User, ApiKey  # noqa: F401
from aijailer.models.cell import Cell  # noqa: F401
from aijailer.models.policy import SecurityPolicy  # noqa: F401
from aijailer.models.execution import Execution  # noqa: F401
from aijailer.models.snapshot import Snapshot, PersistentVolume  # noqa: F401
from aijailer.models.node import Node  # noqa: F401
from aijailer.models.webhook import Webhook  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
