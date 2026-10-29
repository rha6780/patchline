package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/rha6780/patchline/internal/finding"
)

// KEVEntry is a CISA KEV catalog entry.
type KEVEntry struct {
	CVEID      string
	DateAdded  string
	DueDate    string
	Ransomware string
}

// ReplaceKEV replaces the stored KEV catalog.
func (s *Store) ReplaceKEV(ctx context.Context, entries []KEVEntry, version string) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, `DELETE FROM kev_catalog`); err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO kev_catalog (cve_id, date_added, due_date, ransomware) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err = stmt.ExecContext(ctx, e.CVEID, e.DateAdded, e.DueDate, e.Ransomware); err != nil {
			return err
		}
	}
	now := formatTime(s.now())
	for k, v := range map[string]string{"kev.refreshed_at": now, "kev.version": version} {
		if _, err = tx.ExecContext(ctx, `
			INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, k, v, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Setting returns a stored setting ("" when absent).
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// KEVSet returns the CVE ids in the KEV catalog.
func (s *Store) KEVSet(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cve_id FROM kev_catalog`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		set[id] = true
	}
	return set, rows.Err()
}

// SLAFinding is an open finding with its SLA bookkeeping.
type SLAFinding struct {
	Finding
	RemindedDueSoonAt *string
	RemindedOverdueAt *string
}

// OpenFindingsForSLA returns every open finding.
func (s *Store) OpenFindingsForSLA(ctx context.Context) ([]SLAFinding, error) {
	rows, err := s.db.QueryContext(ctx, findingColumns+`, reminded_due_soon_at, reminded_overdue_at
		FROM findings WHERE state NOT IN ('resolved', 'not_affected', 'risk_accepted') ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SLAFinding
	for rows.Next() {
		var soon, overdue sql.NullString
		f, err := scanFinding(extraScanner{rows, []any{&soon, &overdue}})
		if err != nil {
			return nil, err
		}
		sf := SLAFinding{Finding: f}
		if soon.Valid {
			sf.RemindedDueSoonAt = &soon.String
		}
		if overdue.Valid {
			sf.RemindedOverdueAt = &overdue.String
		}
		out = append(out, sf)
	}
	return out, rows.Err()
}

// extraScanner appends destinations for columns after the finding columns.
type extraScanner struct {
	sc    scanner
	extra []any
}

func (e extraScanner) Scan(dest ...any) error { return e.sc.Scan(append(dest, e.extra...)...) }

// SLAUpdate is the policy's verdict for a finding.
type SLAUpdate struct {
	FindingID         int64
	KEV               bool
	EffectiveSeverity string
	Reasons           []string
	Due               *time.Time
	// Silent stores the verdict without a timeline event (first evaluation).
	Silent bool
}

// UpdateSLA stores a verdict. A changed due date clears sent reminders.
// Unless Silent, it records an sla_changed event.
func (s *Store) UpdateSLA(ctx context.Context, u SLAUpdate, prev Finding) (err error) {
	reasons, err := json.Marshal(nonNil(u.Reasons))
	if err != nil {
		return err
	}
	var due sql.NullString
	if u.Due != nil {
		due = sql.NullString{String: formatTime(*u.Due), Valid: true}
	}
	now := formatTime(s.now())

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	dueChanged := (prev.DueAt == nil) != !due.Valid || (prev.DueAt != nil && *prev.DueAt != due.String)
	q := `UPDATE findings SET kev = ?, effective_severity = ?, sla_reasons = ?, due_at = ?`
	if dueChanged {
		q += `, reminded_due_soon_at = NULL, reminded_overdue_at = NULL`
	}
	if _, err = tx.ExecContext(ctx, q+` WHERE id = ?`, u.KEV, u.EffectiveSeverity, string(reasons), due, u.FindingID); err != nil {
		return err
	}
	if !u.Silent {
		ev := map[string]any{
			"from_severity": prev.DisplaySeverity(), "to_severity": u.EffectiveSeverity,
			"reasons": nonNil(u.Reasons), "kev": u.KEV,
		}
		if prev.DueAt != nil {
			ev["from_due"] = *prev.DueAt
		}
		if due.Valid {
			ev["to_due"] = due.String
		}
		if err = insertEvent(ctx, tx, u.FindingID, finding.EventSLAChanged, sql.NullString{}, sql.NullString{}, ev, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Reminder kinds.
const (
	ReminderDueSoon = "due_soon"
	ReminderOverdue = "overdue"
)

// RecordReminder marks a reminder as sent at "at" and adds it to the
// timeline.
func (s *Store) RecordReminder(ctx context.Context, findingID int64, kind, due string, at time.Time) (err error) {
	now := formatTime(at)
	col := "reminded_due_soon_at"
	if kind == ReminderOverdue {
		col = "reminded_overdue_at"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, `UPDATE findings SET `+col+` = ? WHERE id = ?`, now, findingID); err != nil {
		return err
	}
	if err = insertEvent(ctx, tx, findingID, finding.EventReminder, sql.NullString{}, sql.NullString{},
		map[string]any{"kind": kind, "due": due}, now); err != nil {
		return err
	}
	return tx.Commit()
}
