from __future__ import annotations

import logging
import time
from queue import Empty

from .app_state import AppState
from .db import insert_http_logs_batch, insert_ws_logs_batch
from .queue_types import HttpLogEntry, WsLogEntry

logger = logging.getLogger(__name__)


def db_writer_loop(state: AppState) -> None:
    """Thread 3: drain the queue in batches and write to the database."""
    batch_size = 100
    flush_interval_s = 0.5

    http_batch: list[HttpLogEntry] = []
    ws_batch: list[WsLogEntry] = []
    last_flush = time.monotonic()

    logger.info("DB writer thread started")

    while not state.stop_event.is_set():
        # Drain items from queue
        try:
            item = state.queue.get(timeout=0.1)
            if isinstance(item, HttpLogEntry):
                http_batch.append(item)
            elif isinstance(item, WsLogEntry):
                ws_batch.append(item)
        except Empty:
            pass

        # Check if we should flush
        batch_full = (len(http_batch) + len(ws_batch)) >= batch_size
        time_elapsed = (time.monotonic() - last_flush) >= flush_interval_s
        has_items = http_batch or ws_batch

        if has_items and (batch_full or time_elapsed):
            _flush(state, http_batch, ws_batch)
            http_batch = []
            ws_batch = []
            last_flush = time.monotonic()

    # Final flush on shutdown
    if http_batch or ws_batch:
        _flush(state, http_batch, ws_batch)

    logger.info("DB writer thread stopped")


def _flush(state: AppState, http_batch: list[HttpLogEntry], ws_batch: list[WsLogEntry]) -> None:
    try:
        if http_batch:
            insert_http_logs_batch(state.db_pool, http_batch)
            logger.debug("Flushed %d HTTP log entries", len(http_batch))
        if ws_batch:
            insert_ws_logs_batch(state.db_pool, ws_batch)
            logger.debug("Flushed %d WS log entries", len(ws_batch))
    except Exception:
        logger.exception("Error flushing batch to database")

    state.queue_depth = state.queue.qsize()
