-- +goose Up

-- The built-in admin account. It starts with the password "admin" and
-- must_change set; failed logins lock it for a while.
CREATE TABLE local_accounts (
    username            TEXT PRIMARY KEY,
    password_hash       TEXT    NOT NULL,
    must_change         INTEGER NOT NULL DEFAULT 1,
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    locked_until        TEXT,
    password_changed_at TEXT    NOT NULL,
    last_login_at       TEXT
);

-- +goose Down
DROP TABLE local_accounts;
