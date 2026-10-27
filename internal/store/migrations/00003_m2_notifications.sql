-- +goose Up

-- One chat message per finding and sink. last_event_id is the newest
-- finding event already reflected in the message; newer events are posted
-- to the thread and the message is updated.
CREATE TABLE finding_notifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    sink            TEXT    NOT NULL,              -- slack | console
    channel         TEXT    NOT NULL DEFAULT '',   -- sink-side channel id
    message_ref     TEXT    NOT NULL DEFAULT '',   -- sink-side message id (Slack ts); '' = not posted
    last_event_id   INTEGER NOT NULL DEFAULT 0,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (finding_id, sink)
);

-- +goose Down
DROP TABLE finding_notifications;
