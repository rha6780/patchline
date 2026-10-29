-- +goose Up

-- Risk signals and the policy's verdict. effective_severity is '' until
-- the policy has evaluated the finding.
ALTER TABLE findings ADD COLUMN epss                 REAL;
ALTER TABLE findings ADD COLUMN kev                  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN effective_severity   TEXT    NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN sla_reasons          TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE findings ADD COLUMN sla_started_at       TEXT;
ALTER TABLE findings ADD COLUMN reminded_due_soon_at TEXT;
ALTER TABLE findings ADD COLUMN reminded_overdue_at  TEXT;
UPDATE findings SET sla_started_at = first_seen_at;
CREATE INDEX findings_by_due ON findings (state, due_at);

-- CISA Known Exploited Vulnerabilities.
CREATE TABLE kev_catalog (
    cve_id     TEXT PRIMARY KEY,
    date_added TEXT NOT NULL DEFAULT '',
    due_date   TEXT NOT NULL DEFAULT '',
    ransomware TEXT NOT NULL DEFAULT ''
);

-- Small runtime settings (for example when the KEV catalog was refreshed).
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- +goose Down
DROP TABLE settings;
DROP TABLE kev_catalog;
DROP INDEX findings_by_due;
ALTER TABLE findings DROP COLUMN reminded_overdue_at;
ALTER TABLE findings DROP COLUMN reminded_due_soon_at;
ALTER TABLE findings DROP COLUMN sla_started_at;
ALTER TABLE findings DROP COLUMN sla_reasons;
ALTER TABLE findings DROP COLUMN effective_severity;
ALTER TABLE findings DROP COLUMN kev;
ALTER TABLE findings DROP COLUMN epss;
