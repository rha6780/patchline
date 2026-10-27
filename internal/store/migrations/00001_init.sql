-- +goose Up

-- Raw webhook deliveries, stored before processing (inbox pattern).
-- dedup_key makes redelivered events idempotent.
CREATE TABLE webhook_inbox (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT    NOT NULL,              -- dependencytrack | gitea | jenkins
    event_type   TEXT    NOT NULL,
    dedup_key    TEXT    NOT NULL,
    payload      BLOB    NOT NULL,
    received_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    processed_at TEXT,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT,
    UNIQUE (source, dedup_key)
);
CREATE INDEX webhook_inbox_pending ON webhook_inbox (processed_at) WHERE processed_at IS NULL;

-- One row per service x component x vulnerability x environment.
CREATE TABLE findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    service         TEXT NOT NULL,
    environment     TEXT NOT NULL,              -- main | prod | manual
    component_purl  TEXT NOT NULL,              -- purl, or cpe for manual items
    vuln_id         TEXT NOT NULL,              -- canonical id (CVE preferred over GHSA)
    aliases         TEXT NOT NULL DEFAULT '[]', -- JSON array
    severity        TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'new',
    due_at          TEXT,
    first_seen_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    resolved_at     TEXT,
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (service, environment, component_purl, vuln_id)
);
CREATE INDEX findings_open ON findings (state, due_at);

-- Append-only history; the finding timeline is rendered from this table.
CREATE TABLE finding_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    kind        TEXT    NOT NULL,               -- detected | notified | pr_opened | pr_merged | rescanned | deployed | decided | state_changed
    from_state  TEXT,
    to_state    TEXT,
    evidence    TEXT    NOT NULL DEFAULT '{}',  -- JSON: commit sha, pr url, image digest, actor, ...
    occurred_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX finding_events_by_finding ON finding_events (finding_id, occurred_at);

-- +goose Down
DROP TABLE finding_events;
DROP TABLE findings;
DROP TABLE webhook_inbox;
