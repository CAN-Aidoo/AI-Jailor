"""Dialect-portable column types.

Production runs on PostgreSQL and keeps the native JSONB/INET/CIDR/ARRAY
types. Other dialects (SQLite in unit tests) get a compatible fallback so
the same models work everywhere without a Postgres dependency in CI.
"""

from sqlalchemy import JSON, String
from sqlalchemy.dialects import postgresql

JSONB = postgresql.JSONB().with_variant(JSON(), "sqlite")
INET = postgresql.INET().with_variant(String(45), "sqlite")
CIDR = postgresql.CIDR().with_variant(String(49), "sqlite")


def ARRAY(item_type):  # noqa: N802 - mirrors the SQLAlchemy name
    """Native ARRAY on Postgres, JSON list elsewhere."""
    return postgresql.ARRAY(item_type).with_variant(JSON(), "sqlite")
