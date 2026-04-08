from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from queue import Queue
from typing import Any

from .config import Settings


@dataclass
class InterceptRule:
    """A rule that determines which requests to intercept."""

    methods: list[str] = field(default_factory=list)
    host_pattern: str = ""
    path_pattern: str = ""
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "methods": self.methods,
            "host_pattern": self.host_pattern,
            "path_pattern": self.path_pattern,
            "enabled": self.enabled,
        }


@dataclass
class InterceptedFlow:
    """A request currently held in the intercept queue."""

    flow: Any  # mitmproxy HTTPFlow
    event: asyncio.Event
    enqueued_at: float  # time.time()


class AppState:
    """Shared mutable state across all threads."""

    def __init__(self, settings: Settings) -> None:
        self.lock = threading.Lock()

        # Config
        self.logging_active = threading.Event()
        self.logging_active.set()  # logging ON by default
        self.intercept_active = threading.Event()  # interception OFF by default
        self.intercept_rules: list[InterceptRule] = []
        self.proxy_port: int = settings.proxy_port
        self.label: str = "default"
        self.intercept_timeout_s: int = settings.intercept_timeout_s

        # Stats
        self.dropped_count: int = 0
        self.enqueued_total: int = 0
        self.queue_depth: int = 0

        # Runtime refs (set during startup)
        self.queue: Queue | None = None
        self.db_pool: Any = None
        self.mitmproxy_loop: asyncio.AbstractEventLoop | None = None
        self.start_time: float = time.monotonic()
        self.stop_event = threading.Event()
        self.mitmproxy_thread: threading.Thread | None = None

        # Interception state (accessed from mitmproxy thread only)
        self.intercept_queue: dict[str, InterceptedFlow] = {}
        # flow_id -> http_logs.id mapping for WS linkage
        self.flow_to_log_id: dict[str, int] = {}
