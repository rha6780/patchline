-- +goose Up

-- Tokens for tools (CI uploading SBOMs, scanners fetching VEX). Only the
-- SHA-256 of the token is kept; prefix identifies it in lists.
CREATE TABLE api_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    prefix          TEXT NOT NULL,
    hash            TEXT NOT NULL UNIQUE,
    permissions     TEXT NOT NULL DEFAULT '[]',
    created_by      TEXT NOT NULL,
    created_by_name TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    expires_at      TEXT,
    last_used_at    TEXT,
    revoked_at      TEXT
);

-- +goose Down
DROP TABLE api_tokens;
