from __future__ import annotations

import os


class Settings:
    """Load configuration from environment variables."""

    def __init__(self) -> None:
        self.proxy_port: int = int(os.environ.get("PROXY_PORT", "8080"))
        self.db_dsn: str = os.environ.get(
            "DB_DSN", "postgresql://mitmuser:mitmpass@localhost:5432/mitmdb"
        )
        self.queue_maxsize: int = int(os.environ.get("QUEUE_MAXSIZE", "50000"))
        self.db_batch_size: int = int(os.environ.get("DB_BATCH_SIZE", "100"))
        self.db_flush_ms: int = int(os.environ.get("DB_FLUSH_MS", "500"))
        self.intercept_timeout_s: int = int(os.environ.get("INTERCEPT_TIMEOUT_S", "60"))
        self.log_level: str = os.environ.get("LOG_LEVEL", "INFO")
