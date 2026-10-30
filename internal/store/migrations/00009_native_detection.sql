-- +goose Up

-- Which source projects currently report each finding. A finding is resolved
-- when no source reports it any more. Existing findings came from
-- Dependency-Track.
CREATE TABLE finding_sightings (
    finding_id    INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    source        TEXT    NOT NULL,             -- dependencytrack | patchline
    project_id    TEXT    NOT NULL,             -- DT project uuid, or name@version
    first_seen_at TEXT    NOT NULL,
    last_seen_at  TEXT    NOT NULL,
    PRIMARY KEY (finding_id, source, project_id)
);
CREATE INDEX finding_sightings_by_project ON finding_sightings (source, project_id);
INSERT INTO finding_sightings (finding_id, source, project_id, first_seen_at, last_seen_at)
    SELECT id, 'dependencytrack', dt_project_uuid, first_seen_at, updated_at
    FROM findings WHERE dt_project_uuid != '' AND state NOT IN ('resolved');

-- The source whose severity and title a finding shows.
ALTER TABLE findings ADD COLUMN primary_source TEXT NOT NULL DEFAULT 'dependencytrack';

-- The latest component snapshot of each SBOM uploaded to Patchline.
CREATE TABLE sbom_components (
    source     TEXT NOT NULL,
    project_id TEXT NOT NULL,
    purl       TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    version    TEXT NOT NULL DEFAULT '',
    ecosystem  TEXT NOT NULL DEFAULT '',  -- OSV ecosystem, '' when unknown
    package    TEXT NOT NULL DEFAULT '',  -- OSV package name, normalized
    PRIMARY KEY (source, project_id, purl)
);
CREATE INDEX sbom_components_by_package ON sbom_components (ecosystem, package);

-- OSV records, mirrored per ecosystem.
CREATE TABLE osv_vulns (
    id        TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    modified  TEXT NOT NULL,
    withdrawn TEXT NOT NULL DEFAULT '',
    aliases   TEXT NOT NULL DEFAULT '[]',
    summary   TEXT NOT NULL DEFAULT '',
    severity  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE osv_affected (
    vuln_id   TEXT NOT NULL REFERENCES osv_vulns (id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    package   TEXT NOT NULL,              -- normalized like sbom_components.package
    ranges    TEXT NOT NULL DEFAULT '[]', -- [{introduced, fixed, last_affected}]
    versions  TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX osv_affected_by_package ON osv_affected (ecosystem, package);
CREATE INDEX osv_affected_by_vuln ON osv_affected (vuln_id);

-- +goose Down
DROP TABLE osv_affected;
DROP TABLE osv_vulns;
DROP TABLE sbom_components;
ALTER TABLE findings DROP COLUMN primary_source;
DROP TABLE finding_sightings;
