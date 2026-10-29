package store

import (
	"context"
	"database/sql"
)

// SourceProjectStatus is a source project with its latest BOM evidence.
type SourceProjectStatus struct {
	SourceProject
	LastBOMAt string
	UpdatedAt string
}

// ListSourceProjects returns every project seen from sources, unregistered
// first, then by service and name.
func (s *Store) ListSourceProjects(ctx context.Context) ([]SourceProjectStatus, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT source, project_id, name, version, service, registered,
		       COALESCE(last_bom_at, ''), last_commit, last_ref, last_bom_serial, updated_at
		FROM source_projects
		ORDER BY registered, service, name, version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SourceProjectStatus
	for rows.Next() {
		var p SourceProjectStatus
		if err := rows.Scan(&p.Source, &p.ProjectID, &p.Name, &p.Version, &p.Service, &p.Registered,
			&p.LastBOMAt, &p.Commit, &p.Ref, &p.BOMSerial, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// InboxProblem is an inbox item that failed at least once and is not done.
type InboxProblem struct {
	ID            int64
	Source        string
	EventType     string
	Attempts      int
	LastError     string
	ReceivedAt    string
	NextAttemptAt string
}

// ListInboxProblems returns unprocessed items with failed attempts.
func (s *Store) ListInboxProblems(ctx context.Context, limit int) ([]InboxProblem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, source, event_type, attempts, COALESCE(last_error, ''), received_at, COALESCE(next_attempt_at, '')
		FROM webhook_inbox
		WHERE processed_at IS NULL AND attempts > 0
		ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InboxProblem
	for rows.Next() {
		var p InboxProblem
		if err := rows.Scan(&p.ID, &p.Source, &p.EventType, &p.Attempts, &p.LastError, &p.ReceivedAt, &p.NextAttemptAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// NotificationProblem is a finding whose last delivery attempt failed.
type NotificationProblem struct {
	FindingID     int64
	Sink          string
	Attempts      int
	LastError     string
	NextAttemptAt string
}

// ListNotificationProblems returns failed notification attempts.
func (s *Store) ListNotificationProblems(ctx context.Context, limit int) ([]NotificationProblem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT finding_id, sink, attempts, last_error, COALESCE(next_attempt_at, '')
		FROM finding_notifications
		WHERE last_error IS NOT NULL
		ORDER BY updated_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NotificationProblem
	for rows.Next() {
		var p NotificationProblem
		var msg sql.NullString
		if err := rows.Scan(&p.FindingID, &p.Sink, &p.Attempts, &msg, &p.NextAttemptAt); err != nil {
			return nil, err
		}
		p.LastError = msg.String
		out = append(out, p)
	}
	return out, rows.Err()
}

// FindingFacets returns the distinct services and environments that have
// findings, for filter menus.
func (s *Store) FindingFacets(ctx context.Context) (services, environments []string, err error) {
	for _, q := range []struct {
		col string
		out *[]string
	}{{"service", &services}, {"environment", &environments}} {
		rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT `+q.col+` FROM findings ORDER BY `+q.col)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				rows.Close()
				return nil, nil, err
			}
			*q.out = append(*q.out, v)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
	}
	return services, environments, nil
}
