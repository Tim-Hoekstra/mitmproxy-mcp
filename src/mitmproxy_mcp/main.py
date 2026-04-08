from __future__ import annotations

import asyncio
import logging
import signal
import sys
import threading

from .app_state import AppState
from .config import Settings
from .db import create_pool, run_migrations
from .db_writer import db_writer_loop
from .mcp_server import run_mcp_server, set_state

logger = logging.getLogger(__name__)


def _run_mitmproxy(state: AppState) -> None:
    """Thread 1: run mitmproxy with the LoggingAddon."""
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster

    from .addon import LoggingAddon

    # Create a new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    opts = Options(listen_port=state.proxy_port, ssl_insecure=True)
    master = DumpMaster(opts, loop=loop, with_termlog=False)

    addon = LoggingAddon(state)
    master.addons.add(addon)

    # Capture the event loop so the MCP thread can signal intercept events
    state.mitmproxy_loop = loop

    logger.info("mitmproxy listening on port %d", state.proxy_port)
    try:
        loop.run_until_complete(master.run())
    except Exception:
        if not state.stop_event.is_set():
            logger.exception("mitmproxy crashed")


def main() -> None:
    settings = Settings()

    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    logger.info("Starting mitmproxy-mcp")

    # 1. Construct AppState
    state = AppState(settings)

    # 2. Init DB pool and run migrations
    logger.info("Connecting to database: %s", settings.db_dsn.split("@")[-1])
    state.db_pool = create_pool(settings.db_dsn)
    run_migrations(state.db_pool)

    # 3. Create write queue
    from queue import Queue
    state.queue = Queue(maxsize=settings.queue_maxsize)

    # 4. Start DB writer thread (daemon)
    writer_thread = threading.Thread(
        target=db_writer_loop,
        args=(state,),
        daemon=True,
        name="db-writer",
    )
    writer_thread.start()

    # 5. Start mitmproxy thread (daemon)
    mitm_thread = threading.Thread(
        target=_run_mitmproxy,
        args=(state,),
        daemon=True,
        name="mitmproxy",
    )
    state.mitmproxy_thread = mitm_thread
    mitm_thread.start()

    # 6. Set up signal handlers
    def _shutdown(signum, frame):
        logger.info("Received signal %s, shutting down...", signum)
        state.stop_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    # 7. Wire up and run MCP server (blocks main thread on stdio)
    set_state(state)
    logger.info("MCP server starting on stdio")

    try:
        asyncio.run(run_mcp_server())
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutting down...")
        state.stop_event.set()

        # Wait for writer to flush
        writer_thread.join(timeout=5.0)

        # Close DB pool
        if state.db_pool:
            state.db_pool.close()

        logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
