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
    attestation_key: str = Field(default="", alias="ATTESTATION_KEY")
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60

    # Database
    db: DatabaseSettings = DatabaseSettings()

    # Redis
    redis: RedisSettings = RedisSettings()

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
