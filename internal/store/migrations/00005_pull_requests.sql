-- +goose Up

-- The vulnerability as Dependency-Track identifies it, to look up its
-- affected version ranges.
ALTER TABLE findings ADD COLUMN dt_vuln_source TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN dt_vuln_id     TEXT NOT NULL DEFAULT '';

-- Pull requests that change a finding's component.
CREATE TABLE finding_pull_requests (
    finding_id     INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    repository     TEXT    NOT NULL,
    number         INTEGER NOT NULL,
    url            TEXT    NOT NULL,
    title          TEXT    NOT NULL DEFAULT '',
    state          TEXT    NOT NULL,              -- open | merged | closed
    package        TEXT    NOT NULL DEFAULT '',
    from_version   TEXT    NOT NULL DEFAULT '',
    to_version     TEXT    NOT NULL DEFAULT '',
    verdict        TEXT    NOT NULL DEFAULT 'unknown', -- fixes | insufficient | unknown
    verdict_detail TEXT    NOT NULL DEFAULT '',
    head_sha       TEXT    NOT NULL DEFAULT '',
    merge_sha      TEXT    NOT NULL DEFAULT '',
    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    PRIMARY KEY (finding_id, repository, number)
);
CREATE INDEX finding_pull_requests_by_pr ON finding_pull_requests (repository, number);
CREATE INDEX findings_by_repository ON findings (repository, state);

-- +goose Down
DROP INDEX findings_by_repository;
DROP TABLE finding_pull_requests;
ALTER TABLE findings DROP COLUMN dt_vuln_id;
ALTER TABLE findings DROP COLUMN dt_vuln_source;
