-- +goose Up

-- Signed-in users. id_hash is the SHA-256 of the cookie value, so a copy
-- of the database does not hand out live sessions.
CREATE TABLE sessions (
    id_hash    TEXT PRIMARY KEY,
    subject    TEXT NOT NULL,
    email      TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL DEFAULT '',
    groups     TEXT NOT NULL DEFAULT '[]',
    csrf       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX sessions_by_expiry ON sessions (expires_at);

-- OIDC logins in flight: state -> nonce, PKCE verifier and where to return.
CREATE TABLE auth_states (
    state      TEXT PRIMARY KEY,
    nonce      TEXT NOT NULL,
    verifier   TEXT NOT NULL,
    next       TEXT NOT NULL DEFAULT '/',
    expires_at TEXT NOT NULL
);

-- The person working on a finding, and an approved due date that replaces
-- the policy's while the effective severity does not rise above
-- due_override_severity.
ALTER TABLE findings ADD COLUMN assignee              TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN due_override          TEXT;
ALTER TABLE findings ADD COLUMN due_override_severity TEXT NOT NULL DEFAULT '';

-- Risk acceptance and due date extension requests, and their decisions.
CREATE TABLE exception_requests (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id        INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    kind              TEXT    NOT NULL,             -- risk_acceptance | due_extension
    reason            TEXT    NOT NULL,
    requested_due     TEXT,                         -- due_extension only
    requested_by      TEXT    NOT NULL,             -- subject
    requested_by_name TEXT    NOT NULL DEFAULT '',
    requested_at      TEXT    NOT NULL,
    status            TEXT    NOT NULL DEFAULT 'pending', -- pending | approved | rejected | cancelled
    decided_by        TEXT    NOT NULL DEFAULT '',
    decided_by_name   TEXT    NOT NULL DEFAULT '',
    decided_at        TEXT,
    decision_note     TEXT    NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX exception_requests_one_pending
    ON exception_requests (finding_id, kind) WHERE status = 'pending';
CREATE INDEX exception_requests_by_status ON exception_requests (status, requested_at);

-- Who changed what, for actions that are not on a finding's timeline
-- (settings) as well as those that are.
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      TEXT NOT NULL,
    actor_name TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '{}',
    at         TEXT NOT NULL
);
CREATE INDEX audit_log_by_time ON audit_log (at);

-- +goose Down
DROP TABLE audit_log;
DROP TABLE exception_requests;
ALTER TABLE findings DROP COLUMN due_override_severity;
ALTER TABLE findings DROP COLUMN due_override;
ALTER TABLE findings DROP COLUMN assignee;
DROP TABLE auth_states;
DROP TABLE sessions;
