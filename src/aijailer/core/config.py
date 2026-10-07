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
    # Bearer token for GET /metrics (Prometheus). Unset => the endpoint does not exist (404).
    metrics_token: str = Field(default="", alias="METRICS_TOKEN")
    # Bearer token for the operator API (/v1/admin/*: per-tenant quota overrides). Separate from
    # tenant API keys on purpose. Unset => the operator API does not exist (404).
    admin_token: str = Field(default="", alias="ADMIN_TOKEN")
    # Audit log: "auto" = database outside dev, memory in dev. The database backend needs a stable
    # signing secret (checkpoint signatures must verify across restarts) unless AIJAILER_ENV=dev.
    audit_backend: str = Field(default="auto", alias="AUDIT_BACKEND")
    audit_signing_secret: str = Field(default="", alias="AUDIT_SIGNING_SECRET")
    audit_checkpoint_interval_seconds: float = Field(
        default=300.0, alias="AUDIT_CHECKPOINT_INTERVAL_SECONDS")
    # Tenant secret store: "id:base64key[,id2:base64key2]" (32 raw bytes each). Unset => the secret
    # store is DISABLED (API returns 503, brokers get no secrets); there is no insecure default.
    secrets_master_keys: str = Field(default="", alias="SECRETS_MASTER_KEYS")
    secrets_primary_key_id: str = Field(default="", alias="SECRETS_PRIMARY_KEY_ID")
    # AWS KMS (preferred for production): key id/ARN/alias of a symmetric customer-managed key.
    # Credentials come from the standard AWS chain (instance/pod role); never from this config.
    # If SECRETS_MASTER_KEYS is also set, those keys stay as decrypt-only fallback so existing rows
    # can be migrated with SecretStore.rewrap_all.
    secrets_kms_key_id: str = Field(default="", alias="SECRETS_KMS_KEY_ID")
    # Extra key ARNs accepted for DECRYPT only (previous keys after a manual key rotation).
    secrets_kms_allowed_key_ids: str = Field(default="", alias="SECRETS_KMS_ALLOWED_KEY_IDS")
    secrets_kms_region: str = Field(default="", alias="SECRETS_KMS_REGION")
    secrets_kms_endpoint_url: str = Field(default="", alias="SECRETS_KMS_ENDPOINT_URL")
    # How long an unwrapped data key may be cached (0 disables). Also the delay before disabling
    # the KMS key takes effect on this process: it is the kill-switch latency.
    secrets_kms_cache_ttl_seconds: float = Field(default=300.0, alias="SECRETS_KMS_CACHE_TTL_SECONDS", ge=0)
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
    # cgroup v2 limits (cpu/memory) for each VMM. Disabling is refused outside AIJAILER_ENV=dev.
    jailer_use_cgroups: bool = Field(default=True, alias="JAILER_USE_CGROUPS")
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
    snapshot_dir: str = Field(default="/var/lib/aijailer/snapshots", alias="SNAPSHOT_DIR")

    # Rate limiting defaults
    default_rate_limit_per_minute: int = 300

    # Cell defaults
    default_vcpus: int = 1
    default_memory_mb: int = 512
    default_disk_mb: int = 2048
    default_network_bandwidth_mbps: int = 100
    # Hard ceiling for any cell's per-direction limit (create and change). "Unlimited" is not
    # expressible: raise this instead (shaping supports up to 10000).
    max_cell_bandwidth_mbps: int = Field(default=10000, alias="MAX_CELL_BANDWIDTH_MBPS", ge=1, le=10000)

    # CodeImmune: Secure Code Generation
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    constraint_dir: str = Field(default="constraints", alias="CONSTRAINT_DIR")
    immune_memory_enabled: bool = Field(default=True, alias="IMMUNE_MEMORY_ENABLED")

    model_config = {"env_prefix": "", "env_nested_delimiter": "__"}


def get_settings() -> Settings:
    return Settings()
