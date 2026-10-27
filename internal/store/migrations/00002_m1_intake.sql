-- +goose Up

-- Retry scheduling for inbox entries that failed to process.
ALTER TABLE webhook_inbox ADD COLUMN next_attempt_at TEXT;

-- Context needed to display and link findings without calling the source.
ALTER TABLE findings ADD COLUMN registered            INTEGER NOT NULL DEFAULT 1; -- 0: source project not in inventory
ALTER TABLE findings ADD COLUMN repository            TEXT    NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN component_name        TEXT    NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN component_version     TEXT    NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN title                 TEXT    NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN dt_project_uuid       TEXT    NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN dt_component_uuid     TEXT    NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN dt_vulnerability_uuid TEXT    NOT NULL DEFAULT '';

-- Projects seen from sources, with the last BOM time (heartbeat).
CREATE TABLE source_projects (
    source      TEXT    NOT NULL,              -- dependencytrack
    project_id  TEXT    NOT NULL,              -- source-side id (DT project uuid)
    name        TEXT    NOT NULL,
    version     TEXT    NOT NULL DEFAULT '',
    service     TEXT    NOT NULL,
    registered  INTEGER NOT NULL,
    last_bom_at TEXT,
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (source, project_id)
);

-- +goose Down
DROP TABLE source_projects;
ALTER TABLE findings DROP COLUMN dt_vulnerability_uuid;
ALTER TABLE findings DROP COLUMN dt_component_uuid;
ALTER TABLE findings DROP COLUMN dt_project_uuid;
ALTER TABLE findings DROP COLUMN title;
ALTER TABLE findings DROP COLUMN component_version;
ALTER TABLE findings DROP COLUMN component_name;
ALTER TABLE findings DROP COLUMN repository;
ALTER TABLE findings DROP COLUMN registered;
ALTER TABLE webhook_inbox DROP COLUMN next_attempt_at;
