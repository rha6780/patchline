-- +goose Up

-- Evidence from the latest BOM of each source project.
ALTER TABLE source_projects ADD COLUMN last_commit     TEXT NOT NULL DEFAULT '';
ALTER TABLE source_projects ADD COLUMN last_ref        TEXT NOT NULL DEFAULT '';
ALTER TABLE source_projects ADD COLUMN last_bom_serial TEXT NOT NULL DEFAULT '';

-- Reconciliation looks up a project's findings.
CREATE INDEX findings_by_dt_project ON findings (dt_project_uuid, state);

-- +goose Down
DROP INDEX findings_by_dt_project;
ALTER TABLE source_projects DROP COLUMN last_bom_serial;
ALTER TABLE source_projects DROP COLUMN last_ref;
ALTER TABLE source_projects DROP COLUMN last_commit;
