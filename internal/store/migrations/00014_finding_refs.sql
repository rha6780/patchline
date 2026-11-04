-- +goose Up

-- How each tool names a finding: its project, component and vulnerability
-- ids there. One row per source project, kept after the finding is
-- resolved (unlike finding_sightings, which says who reports it now), so
-- links and decision write-back keep working. Replaces findings.dt_*,
-- which are still written until they are dropped.
CREATE TABLE finding_refs (
    finding_id  INTEGER NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    source      TEXT    NOT NULL,              -- dependencytrack | patchline | ...
    project     TEXT    NOT NULL,              -- DT project uuid, or name@version
    component   TEXT    NOT NULL DEFAULT '',   -- DT component uuid, or purl
    vuln        TEXT    NOT NULL DEFAULT '',   -- DT vulnerability uuid, or the vulnerability id
    vuln_source TEXT    NOT NULL DEFAULT '',   -- NVD, GITHUB, OSV, ... (as the tool names it)
    vuln_name   TEXT    NOT NULL DEFAULT '',   -- the id within vuln_source
    PRIMARY KEY (finding_id, source, project)
);
CREATE INDEX finding_refs_by_key ON finding_refs (source, project, component, vuln);

INSERT INTO finding_refs (finding_id, source, project, component, vuln, vuln_source, vuln_name)
    SELECT id, 'dependencytrack', dt_project_uuid, dt_component_uuid, dt_vulnerability_uuid, dt_vuln_source, dt_vuln_id
    FROM findings WHERE dt_project_uuid != '';
INSERT OR IGNORE INTO finding_refs (finding_id, source, project, component, vuln)
    SELECT s.finding_id, s.source, s.project_id, f.component_purl, f.vuln_id
    FROM finding_sightings s JOIN findings f ON f.id = s.finding_id
    WHERE s.source != 'dependencytrack';

-- +goose Down
DROP TABLE finding_refs;
