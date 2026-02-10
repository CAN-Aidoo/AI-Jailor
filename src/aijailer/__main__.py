"""Entry point for running the AI Jailer API server."""

import uvicorn

from aijailer.core.config import get_settings


def main():
    settings = get_settings()
    uvicorn.run(
        "aijailer.api.app:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
