package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ComponentUse is a component in the latest snapshot of a source project,
// with the service and environment it belongs to.
type ComponentUse struct {
	Component
	Source      string `json:"source"`
	ProjectID   string `json:"project_id"`
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Service     string `json:"service"`
	Registered  bool   `json:"registered"`
	LastBOMAt   string `json:"last_bom_at,omitempty"`
	Commit      string `json:"commit,omitempty"`
	// OpenFindings counts the open findings of this component in this
	// service and environment, from any source.
	OpenFindings int `json:"open_findings"`
}

// ComponentQuery narrows SearchComponents. Text matches the purl, name or
// package name (case-insensitive substring); empty fields match everything.
type ComponentQuery struct {
	Text      string
	Ecosystem string
	Package   string // exact, normalized package name
	Limit     int
}

const componentUseColumns = `
	SELECT c.purl, c.name, c.version, c.ecosystem, c.package,
	       c.source, c.project_id, p.name, COALESCE(NULLIF(p.version, ''), 'default'), p.service, p.registered,
	       COALESCE(p.last_bom_at, ''), p.last_commit,
	       (SELECT COUNT(*) FROM findings f
	        WHERE f.service = p.service AND f.environment = COALESCE(NULLIF(p.version, ''), 'default')
	          AND f.component_purl = c.purl AND f.state NOT IN ('resolved', 'not_affected', 'risk_accepted'))
	FROM sbom_components c
	JOIN source_projects p ON p.source = c.source AND p.project_id = c.project_id`

// SearchComponents finds components in the stored snapshots.
func (s *Store) SearchComponents(ctx context.Context, q ComponentQuery) ([]ComponentUse, error) {
	var where []string
	var args []any
	if t := strings.TrimSpace(q.Text); t != "" {
		like := "%" + escapeLike(strings.ToLower(t)) + "%"
		where = append(where, `(lower(c.purl) LIKE ? ESCAPE '\' OR lower(c.name) LIKE ? ESCAPE '\' OR lower(c.package) LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like)
	}
	if q.Ecosystem != "" {
		where = append(where, "c.ecosystem = ?")
		args = append(args, q.Ecosystem)
	}
	if q.Package != "" {
		where = append(where, "c.package = ?")
		args = append(args, q.Package)
	}
	query := componentUseColumns
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	limit := q.Limit
	if limit <= 0 || limit > 10000 {
		limit = 5000
	}
	query += fmt.Sprintf(" ORDER BY c.package, c.name, c.version, p.service, p.version LIMIT %d", limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ComponentUse{}
	for rows.Next() {
		var u ComponentUse
		if err := rows.Scan(&u.PURL, &u.Name, &u.Version, &u.Ecosystem, &u.Package,
			&u.Source, &u.ProjectID, &u.Project, &u.Environment, &u.Service, &u.Registered,
			&u.LastBOMAt, &u.Commit, &u.OpenFindings); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// escapeLike escapes the LIKE wildcards in s (the ESCAPE character is \).
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// OSVRecordsFor returns the OSV records with the id, or listing it as an
// alias (a CVE usually has one GitHub advisory, sometimes several).
func (s *Store) OSVRecordsFor(ctx context.Context, id string) ([]OSVRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ecosystem, modified, withdrawn, aliases, summary, severity FROM osv_vulns
		WHERE id = ? OR EXISTS (SELECT 1 FROM json_each(osv_vulns.aliases) WHERE json_each.value = ?)
		ORDER BY id`, id, id)
	if err != nil {
		return nil, err
	}
	var out []OSVRecord
	for rows.Next() {
		var (
			r       OSVRecord
			aliases string
		)
		if err := rows.Scan(&r.ID, &r.Ecosystem, &r.Modified, &r.Withdrawn, &aliases, &r.Summary, &r.Severity); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal([]byte(aliases), &r.Aliases); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		aff, err := s.osvAffected(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Affected = aff
	}
	return out, nil
}

func (s *Store) osvAffected(ctx context.Context, id string) ([]OSVAffected, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ecosystem, package, ranges, versions FROM osv_affected WHERE vuln_id = ? ORDER BY rowid`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OSVAffected
	for rows.Next() {
		var (
			a                OSVAffected
			ranges, versions string
		)
		if err := rows.Scan(&a.Ecosystem, &a.Package, &ranges, &versions); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(ranges), &a.Ranges); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(versions), &a.Versions); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// FindingsForVuln returns the findings, open or closed and from any
// source, whose id or aliases are among ids.
func (s *Store) FindingsForVuln(ctx context.Context, ids []string) ([]Finding, error) {
	if len(ids) == 0 {
		return []Finding{}, nil
	}
	ph := "?" + strings.Repeat(", ?", len(ids)-1)
	args := make([]any, 0, 2*len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	for _, id := range ids {
		args = append(args, id)
	}
	rows, err := s.db.QueryContext(ctx, findingColumns+` FROM findings
		WHERE vuln_id IN (`+ph+`)
		   OR EXISTS (SELECT 1 FROM json_each(findings.aliases) WHERE json_each.value IN (`+ph+`))
		ORDER BY service, environment, component_purl`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SnapshotFindings returns the findings a source project currently
// reports, in any state.
func (s *Store) SnapshotFindings(ctx context.Context, source, project string) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx, findingColumns+` FROM findings
		WHERE id IN (SELECT finding_id FROM finding_sightings WHERE source = ? AND project_id = ?)
		ORDER BY component_purl, vuln_id`, source, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
