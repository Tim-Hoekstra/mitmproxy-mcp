CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS http_logs (
    id                  BIGSERIAL PRIMARY KEY,
    created_at          TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    -- Request
    req_method          TEXT                NOT NULL,
    req_scheme          TEXT                NOT NULL,
    req_host            TEXT                NOT NULL,
    req_port            INTEGER             NOT NULL,
    req_path            TEXT                NOT NULL,
    req_http_version    TEXT                NOT NULL,
    req_headers         JSONB               NOT NULL DEFAULT '{}',
    req_body            BYTEA,
    req_timestamp_ms    DOUBLE PRECISION    NOT NULL,

    -- Response (nullable — may be absent on error)
    resp_status_code    INTEGER,
    resp_reason         TEXT,
    resp_http_version   TEXT,
    resp_headers        JSONB,
    resp_body           BYTEA,
    resp_timestamp_ms   DOUBLE PRECISION,

    -- Derived
    duration_ms         DOUBLE PRECISION,
    error_message       TEXT,

    -- Annotation
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
