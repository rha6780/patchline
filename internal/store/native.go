package store

import (
	"context"
	"encoding/json"
	"fmt"
)

// Component is one package of a stored SBOM snapshot.
type Component struct {
	PURL      string `json:"purl"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Package   string `json:"package,omitempty"`
	// BOMRef is the component's bom-ref in the uploaded CycloneDX SBOM.
	BOMRef string `json:"bom_ref,omitempty"`
}

// ReplaceComponents makes components the snapshot of a source project.
func (s *Store) ReplaceComponents(ctx context.Context, source, project string, components []Component) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, `DELETE FROM sbom_components WHERE source = ? AND project_id = ?`, source, project); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO sbom_components (source, project_id, purl, name, version, ecosystem, package, bom_ref)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, c := range components {
		if _, err = stmt.ExecContext(ctx, source, project, c.PURL, c.Name, c.Version, c.Ecosystem, c.Package, c.BOMRef); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Components returns the snapshot of a source project.
func (s *Store) Components(ctx context.Context, source, project string) ([]Component, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT purl, name, version, ecosystem, package, bom_ref FROM sbom_components
		WHERE source = ? AND project_id = ? ORDER BY purl`, source, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Component
	for rows.Next() {
		var c Component
		if err := rows.Scan(&c.PURL, &c.Name, &c.Version, &c.Ecosystem, &c.Package, &c.BOMRef); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetSnapshotBOM records the serial and version of the SBOM a snapshot
// came from, exactly (an SBOM without a serial clears it), so VEX
// BOM-Links never point into an older document.
func (s *Store) SetSnapshotBOM(ctx context.Context, source, project, serial string, version int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE source_projects SET last_bom_serial = ?, last_bom_version = ?
		WHERE source = ? AND project_id = ?`, serial, version, source, project)
	return err
}

// SourceProjects returns the projects of a source.
func (s *Store) SourceProjects(ctx context.Context, source string) ([]SourceProject, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT source, project_id, name, version, service, registered, last_commit, last_ref, last_bom_serial, last_bom_version
		FROM source_projects WHERE source = ? ORDER BY name, version`, source)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SourceProject
	for rows.Next() {
		var p SourceProject
		if err := rows.Scan(&p.Source, &p.ProjectID, &p.Name, &p.Version, &p.Service, &p.Registered,
			&p.Commit, &p.Ref, &p.BOMSerial, &p.BOMVersion); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// OSVRange is one affected interval of an OSV record: empty bounds are
// open; Introduced "0" means from the first version.
type OSVRange struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// OSVAffected is an affected package of an OSV record.
type OSVAffected struct {
	Ecosystem string     `json:"ecosystem"`
	Package   string     `json:"package"`
	Ranges    []OSVRange `json:"ranges"`
	Versions  []string   `json:"versions"`
}

// OSVRecord is an OSV vulnerability as Patchline keeps it.
type OSVRecord struct {
	ID        string
	Ecosystem string
	Modified  string
	Withdrawn string
	Aliases   []string
	Summary   string
	Severity  string
	Affected  []OSVAffected
}

// UpsertOSV stores records, replacing earlier versions of the same ids.
func (s *Store) UpsertOSV(ctx context.Context, records []OSVRecord) error {
	return s.WriteOSV(ctx, "", func(put func(OSVRecord) error) error {
		for _, r := range records {
			if err := put(r); err != nil {
				return err
			}
		}
		return nil
	})
}

// WriteOSV stores the records produce hands to put, in one transaction.
// With replaceEcosystem set, the ecosystem's existing records are removed
// first (a full sync), so a lookup never sees a half-loaded ecosystem.
func (s *Store) WriteOSV(ctx context.Context, replaceEcosystem string, produce func(put func(OSVRecord) error) error) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if replaceEcosystem != "" {
		if _, err = tx.ExecContext(ctx, `DELETE FROM osv_vulns WHERE ecosystem = ?`, replaceEcosystem); err != nil {
			return err
		}
	}
	vuln, err := tx.PrepareContext(ctx, `
		INSERT INTO osv_vulns (id, ecosystem, modified, withdrawn, aliases, summary, severity)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET ecosystem = excluded.ecosystem, modified = excluded.modified,
			withdrawn = excluded.withdrawn, aliases = excluded.aliases, summary = excluded.summary,
			severity = excluded.severity`)
	if err != nil {
		return err
	}
	defer vuln.Close()
	clear, err := tx.PrepareContext(ctx, `DELETE FROM osv_affected WHERE vuln_id = ?`)
	if err != nil {
		return err
	}
	defer clear.Close()
	aff, err := tx.PrepareContext(ctx, `
		INSERT INTO osv_affected (vuln_id, ecosystem, package, ranges, versions) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer aff.Close()

	put := func(r OSVRecord) error {
		aliases, err := json.Marshal(nonNil(r.Aliases))
		if err != nil {
			return err
		}
		if _, err := vuln.ExecContext(ctx, r.ID, r.Ecosystem, r.Modified, r.Withdrawn, string(aliases), r.Summary, r.Severity); err != nil {
			return fmt.Errorf("osv %s: %w", r.ID, err)
		}
		if _, err := clear.ExecContext(ctx, r.ID); err != nil {
			return err
		}
		for _, a := range r.Affected {
			ranges, err := json.Marshal(a.Ranges)
			if err != nil {
				return err
			}
			versions, err := json.Marshal(nonNil(a.Versions))
			if err != nil {
				return err
			}
			if _, err := aff.ExecContext(ctx, r.ID, a.Ecosystem, a.Package, string(ranges), string(versions)); err != nil {
				return err
			}
		}
		return nil
	}
	if err = produce(put); err != nil {
		return err
	}
	return tx.Commit()
}

// OSVCandidate is an OSV record affecting a package, with that package's
// ranges.
type OSVCandidate struct {
	ID       string
	Aliases  []string
	Summary  string
	Severity string
	Ranges   []OSVRange
	Versions []string
}

// OSVCandidates returns the live (not withdrawn) records that list the
// package as affected.
func (s *Store) OSVCandidates(ctx context.Context, ecosystem, pkg string) ([]OSVCandidate, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT v.id, v.aliases, v.summary, v.severity, a.ranges, a.versions
		FROM osv_affected a JOIN osv_vulns v ON v.id = a.vuln_id
		WHERE a.ecosystem = ? AND a.package = ? AND v.withdrawn = ''
		ORDER BY v.id`, ecosystem, pkg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OSVCandidate
	for rows.Next() {
		var (
			c                         OSVCandidate
			aliases, ranges, versions string
		)
		if err := rows.Scan(&c.ID, &aliases, &c.Summary, &c.Severity, &ranges, &versions); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(aliases), &c.Aliases); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(ranges), &c.Ranges); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(versions), &c.Versions); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// OSVCount returns how many live records an ecosystem has.
func (s *Store) OSVCount(ctx context.Context, ecosystem string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM osv_vulns WHERE ecosystem = ? AND withdrawn = ''`, ecosystem).Scan(&n)
	return n, err
}

// SetSystemSetting stores a setting Patchline itself maintains (sync
// state), without an audit entry.
func (s *Store) SetSystemSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, formatTime(s.now()))
	return err
}
