"""SDK configuration."""

from dataclasses import dataclass, field


@dataclass
class AiJailerConfig:
    """Configuration for the AI Jailer SDK client."""

    api_key: str = ""
    base_url: str = "https://api.aijailer.com"
    timeout: float = 30.0
    max_retries: int = 3
    retry_backoff_factor: float = 0.5
