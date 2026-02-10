"""Initial schema — all core tables.

Revision ID: 001_initial
Revises: None
Create Date: 2025-01-15
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- tenants ---
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(63), unique=True, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("tier", sa.String(20), nullable=False, server_default="starter"),
        sa.Column("max_concurrent_cells", sa.Integer, nullable=False, server_default="10"),
        sa.Column("max_persistent_storage_gb", sa.Integer, nullable=False, server_default="50"),
        sa.Column("max_snapshot_count", sa.Integer, nullable=False, server_default="100"),
        sa.Column("spending_cap_cents", sa.Integer, nullable=True),
        sa.Column("default_security_policy_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255)),
        sa.Column("role", sa.String(20), nullable=False, server_default="operator"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
    )

    # --- api_keys ---
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("key_hash", sa.String(64), unique=True, nullable=False),
        sa.Column("key_prefix", sa.String(12), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="operator"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("rate_limit_per_minute", sa.Integer),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
    )

    # --- security_policies ---
    op.create_table(
        "security_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("network_policy", postgresql.JSONB, nullable=False),
        sa.Column("filesystem_policy", postgresql.JSONB, nullable=False),
        sa.Column("syscall_policy", postgresql.JSONB, nullable=False),
        sa.Column("resource_policy", postgresql.JSONB, nullable=False),
        sa.Column("capability_policy", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_by", postgresql.UUID(as_uuid=True)),
    )

    # --- nodes ---
    op.create_table(
        "nodes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("hostname", sa.String(255), unique=True, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("total_vcpus", sa.Integer, nullable=False),
        sa.Column("total_memory_mb", sa.Integer, nullable=False),
        sa.Column("total_disk_mb", sa.Integer, nullable=False),
        sa.Column("available_vcpus", sa.Integer, nullable=False),
        sa.Column("available_memory_mb", sa.Integer, nullable=False),
        sa.Column("available_disk_mb", sa.Integer, nullable=False),
        sa.Column("max_cells", sa.Integer, nullable=False),
        sa.Column("running_cells", sa.Integer, nullable=False, server_default="0"),
        sa.Column("internal_ip", postgresql.INET, nullable=False),
        sa.Column("cell_subnet", postgresql.CIDR, nullable=False),
        sa.Column("region", sa.String(50)),
        sa.Column("zone", sa.String(50)),
        sa.Column("labels", postgresql.JSONB, server_default="{}"),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("agent_version", sa.String(50)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # --- cells ---
    op.create_table(
        "cells",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("name", sa.String(255)),
        sa.Column("status", sa.String(20), nullable=False, server_default="creating"),
        sa.Column("error_message", sa.Text),
        sa.Column("image", sa.String(255), nullable=False),
        sa.Column("vcpus", sa.Integer, nullable=False, server_default="1"),
        sa.Column("memory_mb", sa.Integer, nullable=False, server_default="512"),
        sa.Column("disk_mb", sa.Integer, nullable=False, server_default="2048"),
        sa.Column("network_bandwidth_mbps", sa.Integer, nullable=False, server_default="100"),
        sa.Column("security_policy_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("effective_policy", postgresql.JSONB),
        sa.Column("node_id", postgresql.UUID(as_uuid=True)),
        sa.Column("internal_ip", postgresql.INET),
        sa.Column("environment", postgresql.JSONB, server_default="{}"),
        sa.Column("working_directory", sa.String(1024), server_default="/home/agent"),
        sa.Column("persistent_volume_id", postgresql.UUID(as_uuid=True)),
        sa.Column("tags", postgresql.JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("paused_at", sa.DateTime(timezone=True)),
        sa.Column("stopped_at", sa.DateTime(timezone=True)),
        sa.Column("destroyed_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
    )

    # --- executions ---
    op.create_table(
        "executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cell_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="running"),
        sa.Column("command", sa.Text, nullable=False),
        sa.Column("interpreter", sa.String(255)),
        sa.Column("working_directory", sa.String(1024)),
        sa.Column("user_context", sa.String(63), server_default="agent"),
        sa.Column("environment", postgresql.JSONB, server_default="{}"),
        sa.Column("exit_code", sa.Integer),
        sa.Column("stdout", sa.Text),
        sa.Column("stderr", sa.Text),
        sa.Column("cpu_ms", sa.BigInteger),
        sa.Column("memory_peak_mb", sa.Integer),
        sa.Column("timeout_seconds", sa.Integer),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("duration_ms", sa.Integer),
        sa.Column("api_key_id", postgresql.UUID(as_uuid=True)),
        sa.Column("request_id", sa.String(64)),
        sa.ForeignKeyConstraint(["cell_id"], ["cells.id"]),
    )

    # --- persistent_volumes ---
    op.create_table(
        "persistent_volumes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("cell_id", postgresql.UUID(as_uuid=True), index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="creating"),
        sa.Column("size_mb", sa.Integer, nullable=False),
        sa.Column("used_mb", sa.Integer, server_default="0"),
        sa.Column("node_id", postgresql.UUID(as_uuid=True)),
        sa.Column("host_path", sa.String(1024)),
        sa.Column("encrypted", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("encryption_key_id", sa.String(255)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # --- snapshots ---
    op.create_table(
        "snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("cell_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("name", sa.String(255)),
        sa.Column("description", sa.Text),
        sa.Column("status", sa.String(20), nullable=False, server_default="creating"),
        sa.Column("error_message", sa.Text),
        sa.Column("memory_snapshot_key", sa.String(1024)),
        sa.Column("disk_snapshot_key", sa.String(1024)),
        sa.Column("persistent_volume_snapshot_key", sa.String(1024)),
        sa.Column("memory_size_bytes", sa.BigInteger),
        sa.Column("disk_size_bytes", sa.BigInteger),
        sa.Column("total_size_bytes", sa.BigInteger),
        sa.Column("cell_config", postgresql.JSONB, nullable=False),
        sa.Column("retention_policy", sa.String(20), server_default="standard"),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["cell_id"], ["cells.id"]),
    )

    # --- webhooks ---
    op.create_table(
        "webhooks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("events", postgresql.ARRAY(sa.String), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("last_delivery_at", sa.DateTime(timezone=True)),
        sa.Column("last_delivery_status", sa.Integer),
        sa.Column("consecutive_failures", sa.Integer, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
    )

    # --- Indexes for common queries ---
    op.create_index("ix_cells_tenant_status", "cells", ["tenant_id", "status"])
    op.create_index("ix_executions_cell_started", "executions", ["cell_id", "started_at"])
    op.create_index("ix_snapshots_cell_created", "snapshots", ["cell_id", "created_at"])


def downgrade() -> None:
    op.drop_table("webhooks")
    op.drop_table("snapshots")
    op.drop_table("persistent_volumes")
    op.drop_table("executions")
    op.drop_table("cells")
    op.drop_table("nodes")
    op.drop_table("security_policies")
    op.drop_table("api_keys")
    op.drop_table("users")
    op.drop_table("tenants")
