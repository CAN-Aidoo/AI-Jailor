"""Application configuration loaded from environment variables."""

from pydantic import Field
from pydantic_settings import BaseSettings


class DatabaseSettings(BaseSettings):
    url: str = Field(
        default="postgresql+asyncpg://aijailer:aijailer@localhost:5432/aijailer",
        alias="DATABASE_URL",
    )
    pool_size: int = Field(default=20, alias="DATABASE_POOL_SIZE")
    max_overflow: int = Field(default=10, alias="DATABASE_MAX_OVERFLOW")


class RedisSettings(BaseSettings):
    url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")


class Settings(BaseSettings):
    """Root application settings."""

    app_name: str = "AI Jailer"
    debug: bool = Field(default=False, alias="DEBUG")
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")

    # Security
    api_key_header: str = "Authorization"
    jwt_secret: str = Field(default="change-me-in-production", alias="JWT_SECRET")
    # Tenant secret store: "id:base64key[,id2:base64key2]" (32 raw bytes each). Unset => the secret
    # store is DISABLED (API returns 503, brokers get no secrets); there is no insecure default.
    secrets_master_keys: str = Field(default="", alias="SECRETS_MASTER_KEYS")
    secrets_primary_key_id: str = Field(default="", alias="SECRETS_PRIMARY_KEY_ID")
    attestation_key: str = Field(default="", alias="ATTESTATION_KEY")
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60

    # Database
    db: DatabaseSettings = DatabaseSettings()

    # Redis
    redis: RedisSettings = RedisSettings()

    # Environment gate: the simulated engine provides NO isolation and is refused
    # unless environment == "dev".
    environment: str = Field(default="dev", alias="AIJAILER_ENV")
    engine_backend: str = Field(default="simulated", alias="ENGINE_BACKEND")
    jailer_binary: str = Field(default="/usr/bin/jailer", alias="JAILER_BINARY")
    jailer_uid: int = Field(default=10000, alias="JAILER_UID")
    jailer_gid: int = Field(default=10000, alias="JAILER_GID")
    jailer_chroot_base: str = Field(default="/srv/jailer", alias="JAILER_CHROOT_BASE")
    agent_vsock_port: int = 5000
    # auto: enforce iff the engine attaches a real NIC | required: refuse engines that can't
    # be firewalled | off: never provision (only valid for engines with no network)
    network_enforcement: str = Field(default="auto", alias="NETWORK_ENFORCEMENT")
    cell_net_pool: str = Field(default="10.200.0.0/16", alias="CELL_NET_POOL")
    broker_port: int = Field(default=3128, alias="BROKER_PORT")
    # Reconciler: how often to compare the host with the DB, and how long a network must
    # have existed before "not in the DB" counts as stale (DB commit can lag provisioning).
    reconcile_interval_seconds: float = Field(default=30.0, alias="RECONCILE_INTERVAL_SECONDS")
    reconcile_grace_seconds: float = Field(default=120.0, alias="RECONCILE_GRACE_SECONDS")
    # An in-flight cell status unchanged for this long means its owner process died.
    reconcile_stuck_seconds: float = Field(default=600.0, alias="RECONCILE_STUCK_SECONDS")
    # off | observe (log containment tier) | enforce (block code the gate flags)
    execution_gate_mode: str = Field(default="observe", alias="EXECUTION_GATE_MODE")

    # MicroVM Engine
    firecracker_binary: str = Field(
        default="/usr/bin/firecracker", alias="FIRECRACKER_BINARY"
    )
    kernel_image_path: str = Field(
        default="/var/lib/aijailer/vmlinux", alias="KERNEL_IMAGE_PATH"
    )
    rootfs_dir: str = Field(default="/var/lib/aijailer/rootfs", alias="ROOTFS_DIR")
    cell_data_dir: str = Field(default="/var/lib/aijailer/cells", alias="CELL_DATA_DIR")

    # Rate limiting defaults
    default_rate_limit_per_minute: int = 300

    # Cell defaults
    default_vcpus: int = 1
    default_memory_mb: int = 512
    default_disk_mb: int = 2048
    default_network_bandwidth_mbps: int = 100

    # CodeImmune: Secure Code Generation
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    constraint_dir: str = Field(default="constraints", alias="CONSTRAINT_DIR")
    immune_memory_enabled: bool = Field(default=True, alias="IMMUNE_MEMORY_ENABLED")

    model_config = {"env_prefix": "", "env_nested_delimiter": "__"}


def get_settings() -> Settings:
    return Settings()
