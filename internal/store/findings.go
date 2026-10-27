package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/rha6780/patchline/internal/finding"
)

// Finding is a stored finding.
type Finding struct {
	ID               int64    `json:"id"`
	Service          string   `json:"service"`
	Registered       bool     `json:"registered"`
	Repository       string   `json:"repository"`
	Environment      string   `json:"environment"`
	ComponentRef     string   `json:"component_ref"`
	ComponentName    string   `json:"component_name"`
	ComponentVersion string   `json:"component_version"`
	VulnID           string   `json:"vuln_id"`
	Aliases          []string `json:"aliases"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title,omitempty"`
	State            string   `json:"state"`
	DueAt            *string  `json:"due_at,omitempty"`
	FirstSeenAt      string   `json:"first_seen_at"`
	ResolvedAt       *string  `json:"resolved_at,omitempty"`
	UpdatedAt        string   `json:"updated_at"`
	DTProjectUUID    string   `json:"dt_project_uuid,omitempty"`
	DTVulnSource     string   `json:"dt_vuln_source,omitempty"`
	DTVulnID         string   `json:"dt_vuln_id,omitempty"`
}

// UpsertFinding records an observation. A new (service, environment,
// component, vulnerability) creates a finding in state "new" together with a
// "detected" event carrying evidence; a known one only refreshes its
// descriptive fields.
func (s *Store) UpsertFinding(ctx context.Context, obs finding.Observation, evidence map[string]any) (id int64, created bool, err error) {
	aliases, err := json.Marshal(nonNil(obs.Aliases))
	if err != nil {
		return 0, false, err
	}
	now := formatTime(s.now())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var prevSeverity, prevState string
	err = tx.QueryRowContext(ctx, `
		SELECT id, severity, state FROM findings
		WHERE service = ? AND environment = ? AND component_purl = ? AND vuln_id = ?`,
		obs.Service, obs.Environment, obs.ComponentRef, obs.VulnID).Scan(&id, &prevSeverity, &prevState)

	switch {
	case err == nil:
		if finding.State(prevState) == finding.StateResolved {
			// A resolved finding seen again is a regression.
			ev, mErr := json.Marshal(map[string]any{"reason": ReasonSeenAgain, "observation": evidence})
			if mErr != nil {
				err = mErr
				return 0, false, err
			}
			if _, err = tx.ExecContext(ctx,
				`UPDATE findings SET state = ?, resolved_at = NULL WHERE id = ?`, finding.StateReopened, id); err != nil {
				return 0, false, err
			}
			if _, err = tx.ExecContext(ctx, `
				INSERT INTO finding_events (finding_id, kind, from_state, to_state, evidence, occurred_at)
				VALUES (?, ?, ?, ?, ?, ?)`,
				id, finding.EventStateChanged, finding.StateResolved, finding.StateReopened, string(ev), now); err != nil {
				return 0, false, err
			}
		}
		if prevSeverity != obs.Severity {
			ev, mErr := json.Marshal(map[string]any{"from": prevSeverity, "to": obs.Severity, "observation": evidence})
			if mErr != nil {
				err = mErr
				return 0, false, err
			}
			if _, err = tx.ExecContext(ctx, `
				INSERT INTO finding_events (finding_id, kind, evidence, occurred_at) VALUES (?, ?, ?, ?)`,
				id, finding.EventSeverityChanged, string(ev), now); err != nil {
				return 0, false, err
			}
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE findings
			SET aliases = ?, severity = ?, title = ?, registered = ?, repository = ?,
			    component_name = ?, component_version = ?,
			    dt_project_uuid = ?, dt_component_uuid = ?, dt_vulnerability_uuid = ?,
			    dt_vuln_source = ?, dt_vuln_id = ?,
			    updated_at = ?
			WHERE id = ?`,
			string(aliases), obs.Severity, obs.Title, obs.Registered, obs.Repository,
			obs.ComponentName, obs.ComponentVersion,
			obs.DTProjectUUID, obs.DTComponentUUID, obs.DTVulnerabilityUUID,
			obs.DTVulnSource, obs.DTVulnID,
			now, id)
		if err != nil {
			return 0, false, err
		}

	case errors.Is(err, sql.ErrNoRows):
		err = tx.QueryRowContext(ctx, `
			INSERT INTO findings (
				service, environment, component_purl, vuln_id, aliases, severity, state,
				registered, repository, component_name, component_version, title,
				dt_project_uuid, dt_component_uuid, dt_vulnerability_uuid, dt_vuln_source, dt_vuln_id,
				first_seen_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			RETURNING id`,
			obs.Service, obs.Environment, obs.ComponentRef, obs.VulnID, string(aliases), obs.Severity, finding.StateNew,
			obs.Registered, obs.Repository, obs.ComponentName, obs.ComponentVersion, obs.Title,
			obs.DTProjectUUID, obs.DTComponentUUID, obs.DTVulnerabilityUUID, obs.DTVulnSource, obs.DTVulnID,
			now, now).Scan(&id)
		if err != nil {
			return 0, false, err
		}
		ev, mErr := json.Marshal(evidence)
		if mErr != nil {
			err = mErr
			return 0, false, err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO finding_events (finding_id, kind, to_state, evidence, occurred_at)
			VALUES (?, ?, ?, ?, ?)`,
			id, finding.EventDetected, finding.StateNew, string(ev), now)
		if err != nil {
			return 0, false, err
		}
		created = true

	default:
		return 0, false, err
	}

	if err = tx.Commit(); err != nil {
		return 0, false, err
	}
	return id, created, nil
}

// DTKey identifies a finding by its Dependency-Track identifiers.
type DTKey struct {
	ProjectUUID       string
	ComponentUUID     string
	VulnerabilityUUID string
}

// ApplyState moves the findings matching key to state to, when the
// lifecycle allows it, recording a state_changed event with evidence.
// It returns how many findings changed.
func (s *Store) ApplyState(ctx context.Context, key DTKey, to finding.State, evidence map[string]any) (changed int, err error) {
	ev, err := json.Marshal(evidence)
	if err != nil {
		return 0, err
	}
	now := formatTime(s.now())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, state FROM findings
		WHERE dt_project_uuid = ? AND dt_component_uuid = ? AND dt_vulnerability_uuid = ?`,
		key.ProjectUUID, key.ComponentUUID, key.VulnerabilityUUID)
	if err != nil {
		return 0, err
	}
	type row struct {
		id    int64
		state finding.State
	}
	var matches []row
	for rows.Next() {
		var r row
		if err = rows.Scan(&r.id, &r.state); err != nil {
			rows.Close()
			return 0, err
		}
		matches = append(matches, r)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, err
	}

	for _, r := range matches {
		if !finding.CanTransition(r.state, to) {
			continue
		}
		if _, err = tx.ExecContext(ctx,
			`UPDATE findings SET state = ?, updated_at = ? WHERE id = ?`, to, now, r.id); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `
			INSERT INTO finding_events (finding_id, kind, from_state, to_state, evidence, occurred_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			r.id, finding.EventStateChanged, r.state, to, string(ev), now); err != nil {
			return 0, err
		}
		changed++
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return changed, nil
}

// Reasons recorded in state_changed evidence.
const (
	ReasonSeenAgain          = "seen_again"
	ReasonAbsentFromSnapshot = "absent_from_latest_bom"
)

// ResolveMissing resolves the findings of a Dependency-Track project that
// are not in keep (the ids present in the project's latest findings), when
// the lifecycle allows it. Closed findings (not affected, risk accepted)
// are left alone. It returns the ids it resolved.
func (s *Store) ResolveMissing(ctx context.Context, dtProjectUUID string, keep []int64, evidence map[string]any) (resolved []int64, err error) {
	ev, err := json.Marshal(map[string]any{"reason": ReasonAbsentFromSnapshot, "snapshot": evidence})
	if err != nil {
		return nil, err
	}
	keepSet := make(map[int64]bool, len(keep))
	for _, id := range keep {
		keepSet[id] = true
	}
	now := formatTime(s.now())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	rows, err := tx.QueryContext(ctx,
		`SELECT id, state FROM findings WHERE dt_project_uuid = ?`, dtProjectUUID)
	if err != nil {
		return nil, err
	}
	type row struct {
		id    int64
		state finding.State
	}
	var candidates []row
	for rows.Next() {
		var r row
		if err = rows.Scan(&r.id, &r.state); err != nil {
			rows.Close()
			return nil, err
		}
		if !keepSet[r.id] && finding.CanTransition(r.state, finding.StateResolved) {
			candidates = append(candidates, r)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}

	for _, r := range candidates {
		if _, err = tx.ExecContext(ctx,
			`UPDATE findings SET state = ?, resolved_at = ?, updated_at = ? WHERE id = ?`,
			finding.StateResolved, now, now, r.id); err != nil {
			return nil, err
		}
		if _, err = tx.ExecContext(ctx, `
			INSERT INTO finding_events (finding_id, kind, from_state, to_state, evidence, occurred_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			r.id, finding.EventStateChanged, r.state, finding.StateResolved, string(ev), now); err != nil {
			return nil, err
		}
		resolved = append(resolved, r.id)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return resolved, nil
}

// FindingFilter narrows ListFindings. Empty fields match everything.
type FindingFilter struct {
	Service     string
	Environment string
	State       string
	Severity    string
	// Open limits the result to findings that still need action.
	Open  bool
	Limit int
}

// ListFindings returns findings, most severe and most recent first.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]Finding, error) {
	var where []string
	var args []any
	for _, c := range []struct{ col, v string }{
		{"service", f.Service}, {"environment", f.Environment}, {"state", f.State}, {"severity", f.Severity},
	} {
		if c.v != "" {
			where = append(where, c.col+" = ?")
			args = append(args, c.v)
		}
	}
	if f.Open {
		where = append(where, "state NOT IN ('resolved', 'not_affected', 'risk_accepted')")
	}
	q := findingColumns + ` FROM findings`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += ` ORDER BY CASE severity
	           WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
	           WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END,
	         first_seen_at DESC, id DESC`
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = 200
	case limit > 10000:
		limit = 10000
	}
	q += fmt.Sprintf(" LIMIT %d", limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Finding{}
	for rows.Next() {
		r, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

const findingColumns = `SELECT id, service, registered, repository, environment, component_purl,
	component_name, component_version, vuln_id, aliases, severity, title,
	state, due_at, first_seen_at, resolved_at, updated_at, dt_project_uuid, dt_vuln_source, dt_vuln_id`

type scanner interface{ Scan(dest ...any) error }

func scanFinding(sc scanner) (Finding, error) {
	var (
		r        Finding
		aliases  string
		due      sql.NullString
		resolved sql.NullString
	)
	if err := sc.Scan(&r.ID, &r.Service, &r.Registered, &r.Repository, &r.Environment, &r.ComponentRef,
		&r.ComponentName, &r.ComponentVersion, &r.VulnID, &aliases, &r.Severity, &r.Title,
		&r.State, &due, &r.FirstSeenAt, &resolved, &r.UpdatedAt, &r.DTProjectUUID, &r.DTVulnSource, &r.DTVulnID); err != nil {
		return Finding{}, err
	}
	if err := json.Unmarshal([]byte(aliases), &r.Aliases); err != nil {
		return Finding{}, fmt.Errorf("finding %d: aliases: %w", r.ID, err)
	}
	if due.Valid {
		r.DueAt = &due.String
	}
	if resolved.Valid {
		r.ResolvedAt = &resolved.String
	}
	return r, nil
}

// GetFinding returns one finding.
func (s *Store) GetFinding(ctx context.Context, id int64) (Finding, error) {
	return scanFinding(s.db.QueryRowContext(ctx, findingColumns+` FROM findings WHERE id = ?`, id))
}

// FindingEvent is one entry of a finding's timeline.
type FindingEvent struct {
	ID         int64           `json:"id"`
	Kind       string          `json:"kind"`
	FromState  *string         `json:"from_state,omitempty"`
	ToState    *string         `json:"to_state,omitempty"`
	Evidence   json.RawMessage `json:"evidence"`
	OccurredAt string          `json:"occurred_at"`
}

// FindingEvents returns a finding's events in order.
func (s *Store) FindingEvents(ctx context.Context, findingID int64) ([]FindingEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, kind, from_state, to_state, evidence, occurred_at
		FROM finding_events WHERE finding_id = ? ORDER BY occurred_at, id`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FindingEvent{}
	for rows.Next() {
		var (
			e        FindingEvent
			from, to sql.NullString
			ev       string
		)
		if err := rows.Scan(&e.ID, &e.Kind, &from, &to, &ev, &e.OccurredAt); err != nil {
			return nil, err
		}
		if from.Valid {
			e.FromState = &from.String
		}
		if to.Valid {
			e.ToState = &to.String
		}
		e.Evidence = json.RawMessage(ev)
		out = append(out, e)
	}
	return out, rows.Err()
}

// SourceProject is a project seen from a source.
type SourceProject struct {
	Source     string
	ProjectID  string
	Name       string
	Version    string
	Service    string
	Registered bool
	// Evidence from the latest BOM; empty values keep what is stored.
	Commit    string
	Ref       string
	BOMSerial string
}

// TouchSourceProject records that a source project was seen, and when bom
// is true, that a new BOM was processed for it.
func (s *Store) TouchSourceProject(ctx context.Context, p SourceProject, bom bool) error {
	now := formatTime(s.now())
	var bomAt sql.NullString
	if bom {
		bomAt = sql.NullString{String: now, Valid: true}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO source_projects (source, project_id, name, version, service, registered, last_bom_at,
		                             last_commit, last_ref, last_bom_serial, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (source, project_id) DO UPDATE SET
			name = excluded.name, version = excluded.version, service = excluded.service,
			registered = excluded.registered,
			last_bom_at = COALESCE(excluded.last_bom_at, source_projects.last_bom_at),
			last_commit = CASE WHEN excluded.last_commit != '' THEN excluded.last_commit ELSE source_projects.last_commit END,
			last_ref = CASE WHEN excluded.last_ref != '' THEN excluded.last_ref ELSE source_projects.last_ref END,
			last_bom_serial = CASE WHEN excluded.last_bom_serial != '' THEN excluded.last_bom_serial ELSE source_projects.last_bom_serial END,
			updated_at = excluded.updated_at`,
		p.Source, p.ProjectID, p.Name, p.Version, p.Service, p.Registered, bomAt,
		p.Commit, p.Ref, p.BOMSerial, now)
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
