from __future__ import annotations

import json
import logging

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .queue_types import HttpLogEntry, WsLogEntry

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS http_logs (
    id                  BIGSERIAL PRIMARY KEY,
    created_at          TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    req_method          TEXT                NOT NULL,
    req_scheme          TEXT                NOT NULL,
    req_host            TEXT                NOT NULL,
    req_port            INTEGER             NOT NULL,
    req_path            TEXT                NOT NULL,
    req_http_version    TEXT                NOT NULL,
    req_headers         JSONB               NOT NULL DEFAULT '{}',
    req_body            BYTEA,
    req_timestamp_ms    DOUBLE PRECISION    NOT NULL,
    resp_status_code    INTEGER,
    resp_reason         TEXT,
    resp_http_version   TEXT,
    resp_headers        JSONB,
    resp_body           BYTEA,
    resp_timestamp_ms   DOUBLE PRECISION,
    duration_ms         DOUBLE PRECISION,
    error_message       TEXT,
    note                TEXT,
    tags                TEXT[]
);

CREATE INDEX IF NOT EXISTS idx_http_logs_created_at  ON http_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_http_logs_req_host    ON http_logs (req_host);
CREATE INDEX IF NOT EXISTS idx_http_logs_req_method  ON http_logs (req_method);
CREATE INDEX IF NOT EXISTS idx_http_logs_resp_status ON http_logs (resp_status_code);
CREATE INDEX IF NOT EXISTS idx_http_logs_host_trgm   ON http_logs USING gin (req_host  gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_http_logs_path_trgm   ON http_logs USING gin (req_path  gin_trgm_ops);

CREATE TABLE IF NOT EXISTS ws_logs (
    id              BIGSERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    http_log_id     BIGINT              REFERENCES http_logs(id) ON DELETE SET NULL,
    direction       TEXT                NOT NULL
                        CHECK (direction IN ('CLIENT_TO_SERVER','SERVER_TO_CLIENT')),
    payload         BYTEA               NOT NULL,
    is_text         BOOLEAN             NOT NULL DEFAULT TRUE,
    timestamp_ms    DOUBLE PRECISION    NOT NULL,
    note            TEXT
);

CREATE INDEX IF NOT EXISTS idx_ws_logs_created_at  ON ws_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ws_logs_http_log_id ON ws_logs (http_log_id);

CREATE TABLE IF NOT EXISTS config_snapshots (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by  TEXT        NOT NULL DEFAULT 'agent',
    config_json JSONB       NOT NULL
);
"""


def create_pool(dsn: str, min_size: int = 2, max_size: int = 10) -> ConnectionPool:
    return ConnectionPool(
        dsn,
        min_size=min_size,
        max_size=max_size,
        kwargs={"row_factory": dict_row},
    )


def run_migrations(pool: ConnectionPool) -> None:
    with pool.connection() as conn:
        conn.execute(SCHEMA_SQL)
        conn.commit()
    logger.info("Database migrations applied")


# ---------------------------------------------------------------------------
# Insert helpers
# ---------------------------------------------------------------------------

def insert_http_log(pool: ConnectionPool, entry: HttpLogEntry) -> int:
    """Insert a single HTTP log entry and return its id."""
    with pool.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO http_logs (
                req_method, req_scheme, req_host, req_port, req_path,
                req_http_version, req_headers, req_body, req_timestamp_ms,
                resp_status_code, resp_reason, resp_http_version,
                resp_headers, resp_body, resp_timestamp_ms,
                duration_ms, error_message
            ) VALUES (
                %(req_method)s, %(req_scheme)s, %(req_host)s, %(req_port)s, %(req_path)s,
                %(req_http_version)s, %(req_headers)s, %(req_body)s, %(req_timestamp_ms)s,
                %(resp_status_code)s, %(resp_reason)s, %(resp_http_version)s,
                %(resp_headers)s, %(resp_body)s, %(resp_timestamp_ms)s,
                %(duration_ms)s, %(error_message)s
            ) RETURNING id
            """,
            {
                "req_method": entry.req_method,
                "req_scheme": entry.req_scheme,
                "req_host": entry.req_host,
                "req_port": entry.req_port,
                "req_path": entry.req_path,
                "req_http_version": entry.req_http_version,
                "req_headers": json.dumps(entry.req_headers),
                "req_body": entry.req_body,
                "req_timestamp_ms": entry.req_timestamp_ms,
                "resp_status_code": entry.resp_status_code,
                "resp_reason": entry.resp_reason,
                "resp_http_version": entry.resp_http_version,
                "resp_headers": json.dumps(entry.resp_headers) if entry.resp_headers else None,
                "resp_body": entry.resp_body,
                "resp_timestamp_ms": entry.resp_timestamp_ms,
                "duration_ms": entry.duration_ms,
                "error_message": entry.error_message,
            },
        ).fetchone()
        conn.commit()
        return row["id"]


def insert_http_logs_batch(pool: ConnectionPool, entries: list[HttpLogEntry]) -> list[int]:
    """Batch insert HTTP log entries, return list of ids."""
    if not entries:
        return []
    ids = []
    with pool.connection() as conn:
        for entry in entries:
            row = conn.execute(
                """
                INSERT INTO http_logs (
                    req_method, req_scheme, req_host, req_port, req_path,
                    req_http_version, req_headers, req_body, req_timestamp_ms,
                    resp_status_code, resp_reason, resp_http_version,
                    resp_headers, resp_body, resp_timestamp_ms,
                    duration_ms, error_message
                ) VALUES (
                    %(req_method)s, %(req_scheme)s, %(req_host)s, %(req_port)s, %(req_path)s,
                    %(req_http_version)s, %(req_headers)s, %(req_body)s, %(req_timestamp_ms)s,
                    %(resp_status_code)s, %(resp_reason)s, %(resp_http_version)s,
                    %(resp_headers)s, %(resp_body)s, %(resp_timestamp_ms)s,
                    %(duration_ms)s, %(error_message)s
                ) RETURNING id
                """,
                {
                    "req_method": entry.req_method,
                    "req_scheme": entry.req_scheme,
                    "req_host": entry.req_host,
                    "req_port": entry.req_port,
                    "req_path": entry.req_path,
                    "req_http_version": entry.req_http_version,
                    "req_headers": json.dumps(entry.req_headers),
                    "req_body": entry.req_body,
                    "req_timestamp_ms": entry.req_timestamp_ms,
                    "resp_status_code": entry.resp_status_code,
                    "resp_reason": entry.resp_reason,
                    "resp_http_version": entry.resp_http_version,
                    "resp_headers": json.dumps(entry.resp_headers) if entry.resp_headers else None,
                    "resp_body": entry.resp_body,
                    "resp_timestamp_ms": entry.resp_timestamp_ms,
                    "duration_ms": entry.duration_ms,
                    "error_message": entry.error_message,
                },
            ).fetchone()
            ids.append(row["id"])
        conn.commit()
    return ids


def insert_ws_log(pool: ConnectionPool, entry: WsLogEntry) -> int:
    with pool.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO ws_logs (http_log_id, direction, payload, is_text, timestamp_ms)
            VALUES (%(http_log_id)s, %(direction)s, %(payload)s, %(is_text)s, %(timestamp_ms)s)
            RETURNING id
            """,
            {
                "http_log_id": entry.http_log_id,
                "direction": entry.direction,
                "payload": entry.payload,
                "is_text": entry.is_text,
                "timestamp_ms": entry.timestamp_ms,
            },
        ).fetchone()
        conn.commit()
        return row["id"]


def insert_ws_logs_batch(pool: ConnectionPool, entries: list[WsLogEntry]) -> list[int]:
    if not entries:
        return []
    ids = []
    with pool.connection() as conn:
        for entry in entries:
            row = conn.execute(
                """
                INSERT INTO ws_logs (http_log_id, direction, payload, is_text, timestamp_ms)
                VALUES (%(http_log_id)s, %(direction)s, %(payload)s, %(is_text)s, %(timestamp_ms)s)
                RETURNING id
                """,
                {
                    "http_log_id": entry.http_log_id,
                    "direction": entry.direction,
                    "payload": entry.payload,
                    "is_text": entry.is_text,
                    "timestamp_ms": entry.timestamp_ms,
                },
            ).fetchone()
            ids.append(row["id"])
        conn.commit()
    return ids


def insert_config_snapshot(pool: ConnectionPool, config: dict) -> None:
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO config_snapshots (config_json) VALUES (%s)",
            (json.dumps(config),),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_http_logs(pool: ConnectionPool, count: int = 20, offset: int = 0) -> tuple[int, list[dict]]:
    """Return (total, entries) for paginated HTTP log listing."""
    with pool.connection() as conn:
        total_row = conn.execute("SELECT count(*) AS total FROM http_logs").fetchone()
        total = total_row["total"]
        rows = conn.execute(
            """
            SELECT id, created_at, req_method, req_scheme, req_host, req_port, req_path,
                   resp_status_code, duration_ms,
                   octet_length(req_body) AS req_body_size,
                   octet_length(resp_body) AS resp_body_size,
                   note, error_message
            FROM http_logs
            ORDER BY id DESC
            LIMIT %(count)s OFFSET %(offset)s
            """,
            {"count": count, "offset": offset},
        ).fetchall()
        return total, rows


def get_http_logs_regex(
    pool: ConnectionPool,
    pattern: str,
    search_fields: list[str] | None = None,
    count: int = 20,
    offset: int = 0,
) -> tuple[int, list[dict]]:
    """Regex search across HTTP history."""
    if search_fields is None:
        search_fields = ["url", "req_headers", "resp_headers", "req_body", "resp_body"]

    conditions = []
    if "url" in search_fields:
        conditions.append("(req_host || req_path) ~* %(pattern)s")
    if "req_headers" in search_fields:
        conditions.append(
            "EXISTS (SELECT 1 FROM jsonb_each_text(req_headers) h WHERE h.value ~* %(pattern)s)"
        )
    if "resp_headers" in search_fields:
        conditions.append(
            "EXISTS (SELECT 1 FROM jsonb_each_text(COALESCE(resp_headers, '{}')) h WHERE h.value ~* %(pattern)s)"
        )
    if "req_body" in search_fields:
        conditions.append(
            "req_body IS NOT NULL AND convert_from(req_body, 'UTF8') ~* %(pattern)s"
        )
    if "resp_body" in search_fields:
        conditions.append(
            "resp_body IS NOT NULL AND convert_from(resp_body, 'UTF8') ~* %(pattern)s"
        )

    if not conditions:
        return 0, []

    where = " OR ".join(conditions)

    with pool.connection() as conn:
        total_row = conn.execute(
            f"SELECT count(*) AS total FROM http_logs WHERE {where}",
            {"pattern": pattern},
        ).fetchone()
        total = total_row["total"]

        rows = conn.execute(
            f"""
            SELECT id, created_at, req_method, req_scheme, req_host, req_port, req_path,
                   resp_status_code, duration_ms,
                   octet_length(req_body) AS req_body_size,
                   octet_length(resp_body) AS resp_body_size,
                   note, error_message
            FROM http_logs
            WHERE {where}
            ORDER BY id DESC
            LIMIT %(count)s OFFSET %(offset)s
            """,
            {"pattern": pattern, "count": count, "offset": offset},
        ).fetchall()
        return total, rows


def get_http_log_by_id(pool: ConnectionPool, log_id: int) -> dict | None:
    with pool.connection() as conn:
        return conn.execute(
            "SELECT * FROM http_logs WHERE id = %s", (log_id,)
        ).fetchone()


def get_http_logs_by_ids(pool: ConnectionPool, log_ids: list[int]) -> list[dict]:
    with pool.connection() as conn:
        return conn.execute(
            "SELECT * FROM http_logs WHERE id = ANY(%s) ORDER BY id",
            (log_ids,),
        ).fetchall()


def get_ws_logs(
    pool: ConnectionPool, count: int = 50, offset: int = 0, http_log_id: int | None = None
) -> tuple[int, list[dict]]:
    extra_where = ""
    params: dict = {"count": count, "offset": offset}
    if http_log_id is not None:
        extra_where = "WHERE http_log_id = %(http_log_id)s"
        params["http_log_id"] = http_log_id

    with pool.connection() as conn:
        total_row = conn.execute(
            f"SELECT count(*) AS total FROM ws_logs {extra_where}", params
        ).fetchone()
        total = total_row["total"]
        rows = conn.execute(
            f"""
            SELECT id, created_at, http_log_id, direction, payload, is_text, note
            FROM ws_logs {extra_where}
            ORDER BY id DESC
            LIMIT %(count)s OFFSET %(offset)s
            """,
            params,
        ).fetchall()
        return total, rows


def get_ws_logs_regex(
    pool: ConnectionPool,
    pattern: str,
    direction: str | None = None,
    count: int = 50,
    offset: int = 0,
) -> tuple[int, list[dict]]:
    conditions = ["is_text = true", "convert_from(payload, 'UTF8') ~* %(pattern)s"]
    params: dict = {"pattern": pattern, "count": count, "offset": offset}
    if direction:
        conditions.append("direction = %(direction)s")
        params["direction"] = direction

    where = " AND ".join(conditions)

    with pool.connection() as conn:
        total_row = conn.execute(
            f"SELECT count(*) AS total FROM ws_logs WHERE {where}", params
        ).fetchone()
        total = total_row["total"]
        rows = conn.execute(
            f"""
            SELECT id, created_at, http_log_id, direction, payload, is_text, note
            FROM ws_logs WHERE {where}
            ORDER BY id DESC
            LIMIT %(count)s OFFSET %(offset)s
            """,
            params,
        ).fetchall()
        return total, rows


def update_note(pool: ConnectionPool, table: str, log_id: int, note: str) -> bool:
    if table not in ("http_logs", "ws_logs"):
        raise ValueError(f"Invalid table: {table}")
    with pool.connection() as conn:
        cur = conn.execute(
            f"UPDATE {table} SET note = %s WHERE id = %s", (note, log_id)
        )
        conn.commit()
        return cur.rowcount > 0


def health_check(pool: ConnectionPool) -> bool:
    try:
        with pool.connection(timeout=1.0) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False
