"""Shared test fixtures."""

import hashlib
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aijailer.api.app import create_app
from aijailer.db.base import Base, get_db
from aijailer.models.tenant import ApiKey, Tenant

# Use SQLite for tests (in-memory)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
async def db_engine():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(db_engine):
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest.fixture
async def test_tenant(db_session: AsyncSession):
    tenant = Tenant(
        name="Test Tenant",
        slug="test-tenant",
        status="active",
        tier="pro",
        max_concurrent_cells=100,
    )
    db_session.add(tenant)
    await db_session.commit()
    return tenant


@pytest.fixture
async def test_api_key(db_session: AsyncSession, test_tenant: Tenant):
    raw_key = "aj_test_12345678"
    api_key = ApiKey(
        tenant_id=test_tenant.id,
        created_by=test_tenant.id,  # simplified for test
        name="Test Key",
        key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
        key_prefix="aj_test_1234",
        role="admin",
        status="active",
    )
    db_session.add(api_key)
    await db_session.commit()
    return raw_key


@pytest.fixture
async def client(db_engine, db_session, test_tenant, test_api_key):
    app = create_app()

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        ac.headers["Authorization"] = f"Bearer {test_api_key}"
        yield ac
