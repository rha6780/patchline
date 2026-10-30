package store

import (
	"context"
	"strings"
)

// ProjectRef is a source project of a service, with where its latest SBOM
// came from.
type ProjectRef struct {
	Source      string `json:"source"`
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Repository  string `json:"repository,omitempty"`
	Branch      string `json:"branch,omitempty"` // refs/heads/ and refs/tags/ trimmed
	Ref         string `json:"ref,omitempty"`
	Commit      string `json:"commit,omitempty"`
	LastBOMAt   string `json:"last_bom_at,omitempty"`
}

// ShortRef trims refs/heads/ and refs/tags/ from a git ref.
func ShortRef(ref string) string {
	if b, ok := strings.CutPrefix(ref, "refs/heads/"); ok {
		return b
	}
	if t, ok := strings.CutPrefix(ref, "refs/tags/"); ok {
		return t
	}
	return ref
}

// ServiceProjects returns the source projects mapped to a service.
func (s *Store) ServiceProjects(ctx context.Context, service string) ([]ProjectRef, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.source, p.name, COALESCE(NULLIF(p.version, ''), 'default'), p.last_ref, p.last_commit,
		       COALESCE(p.last_bom_at, ''),
		       COALESCE((SELECT f.repository FROM finding_sightings g JOIN findings f ON f.id = g.finding_id
		                 WHERE g.source = p.source AND g.project_id = p.project_id AND f.repository != '' LIMIT 1), '')
		FROM source_projects p WHERE p.service = ?
		ORDER BY p.name, p.version, p.source`, service)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProjectRef{}
	for rows.Next() {
		var p ProjectRef
		if err := rows.Scan(&p.Source, &p.Project, &p.Environment, &p.Ref, &p.Commit, &p.LastBOMAt, &p.Repository); err != nil {
			return nil, err
		}
		p.Branch = ShortRef(p.Ref)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Branches returns the branches and tags the latest SBOMs came from,
// across all source projects, for filter menus.
func (s *Store) Branches(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT last_ref FROM source_projects WHERE last_ref != '' ORDER BY last_ref`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	out := []string{}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, err
		}
		if b := ShortRef(ref); !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	return out, rows.Err()
}
