package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/finding"
)

// Actor is the signed-in person behind a change.
type Actor struct {
	Subject string
	Name    string
}

// Label is the name to show, falling back to the subject.
func (a Actor) Label() string {
	if a.Name != "" {
		return a.Name
	}
	return a.Subject
}

// ---- sessions ---------------------------------------------------------

// Session is a signed-in user. Groups are re-mapped to permissions on
// every request, so a changed access policy applies without a new login.
type Session struct {
	IDHash    string
	Subject   string
	Email     string
	Name      string
	Groups    []string
	CSRF      string
	CreatedAt string
	ExpiresAt string
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	groups, err := json.Marshal(nonNil(sess.Groups))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sessions (id_hash, subject, email, name, groups, csrf, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.IDHash, sess.Subject, sess.Email, sess.Name, string(groups), sess.CSRF, sess.CreatedAt, sess.ExpiresAt)
	return err
}

// GetSession returns an unexpired session, or sql.ErrNoRows.
func (s *Store) GetSession(ctx context.Context, idHash string) (Session, error) {
	var (
		sess   Session
		groups string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id_hash, subject, email, name, groups, csrf, created_at, expires_at
		FROM sessions WHERE id_hash = ? AND expires_at > ?`, idHash, formatTime(s.now())).
		Scan(&sess.IDHash, &sess.Subject, &sess.Email, &sess.Name, &groups, &sess.CSRF, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		return Session{}, err
	}
	if err := json.Unmarshal([]byte(groups), &sess.Groups); err != nil {
		return Session{}, fmt.Errorf("session groups: %w", err)
	}
	return sess, nil
}

// DeleteSession signs a session out.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// AuthState is an OIDC login in flight.
type AuthState struct {
	State     string
	Nonce     string
	Verifier  string
	Next      string
	ExpiresAt string
}

// SaveAuthState stores a login in flight and drops expired ones and
// expired sessions.
func (s *Store) SaveAuthState(ctx context.Context, a AuthState) error {
	now := formatTime(s.now())
	if _, err := s.db.ExecContext(ctx, `DELETE FROM auth_states WHERE expires_at <= ?`, now); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_states (state, nonce, verifier, next, expires_at) VALUES (?, ?, ?, ?, ?)`,
		a.State, a.Nonce, a.Verifier, a.Next, a.ExpiresAt)
	return err
}

// TakeAuthState returns and deletes a login in flight, so each state is
// used once. It returns sql.ErrNoRows when it is unknown or expired.
func (s *Store) TakeAuthState(ctx context.Context, state string) (AuthState, error) {
	var a AuthState
	err := s.db.QueryRowContext(ctx, `
		DELETE FROM auth_states WHERE state = ? AND expires_at > ?
		RETURNING state, nonce, verifier, next, expires_at`, state, formatTime(s.now())).
		Scan(&a.State, &a.Nonce, &a.Verifier, &a.Next, &a.ExpiresAt)
	return a, err
}

// ---- assignment -------------------------------------------------------

// AssignFinding sets (or, with "", clears) a finding's assignee and adds
// the change to its timeline. It reports whether anything changed.
func (s *Store) AssignFinding(ctx context.Context, id int64, assignee string, by Actor) (changed bool, err error) {
	assignee = strings.TrimSpace(assignee)
	now := formatTime(s.now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	var prev string
	if err = tx.QueryRowContext(ctx, `SELECT assignee FROM findings WHERE id = ?`, id).Scan(&prev); err != nil {
		return false, err
	}
	if prev == assignee {
		return false, tx.Commit()
	}
	if _, err = tx.ExecContext(ctx, `UPDATE findings SET assignee = ?, updated_at = ? WHERE id = ?`, assignee, now, id); err != nil {
		return false, err
	}
	ev := map[string]any{"from": prev, "to": assignee, "by": by.Subject, "by_name": by.Label()}
	if err = insertEvent(ctx, tx, id, finding.EventAssigned, sql.NullString{}, sql.NullString{}, ev, now); err != nil {
		return false, err
	}
	if err = insertAudit(ctx, tx, by, "finding.assign", fmt.Sprint(id), ev, now); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// ---- exception requests -----------------------------------------------

// Request kinds and statuses.
const (
	RequestRiskAcceptance = "risk_acceptance"
	RequestDueExtension   = "due_extension"

	RequestPending   = "pending"
	RequestApproved  = "approved"
	RequestRejected  = "rejected"
	RequestCancelled = "cancelled"
)

// ErrPendingRequest means the finding already has a pending request of
// that kind.
var ErrPendingRequest = errors.New("a request of this kind is already pending")

// ErrNotPending means the request was decided or cancelled already.
var ErrNotPending = errors.New("request is no longer pending")

// ExceptionRequest asks to accept a finding's risk or to move its due date.
type ExceptionRequest struct {
	ID              int64   `json:"id"`
	FindingID       int64   `json:"finding_id"`
	Kind            string  `json:"kind"`
	Reason          string  `json:"reason"`
	RequestedDue    *string `json:"requested_due,omitempty"`
	RequestedBy     string  `json:"requested_by"`
	RequestedByName string  `json:"requested_by_name,omitempty"`
	RequestedAt     string  `json:"requested_at"`
	Status          string  `json:"status"`
	DecidedBy       string  `json:"decided_by,omitempty"`
	DecidedByName   string  `json:"decided_by_name,omitempty"`
	DecidedAt       *string `json:"decided_at,omitempty"`
	DecisionNote    string  `json:"decision_note,omitempty"`

	// Finding context, filled by ListRequests.
	VulnID      string `json:"vuln_id,omitempty"`
	Service     string `json:"service,omitempty"`
	Environment string `json:"environment,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

// CreateRequest stores a pending request and adds it to the finding's
// timeline.
func (s *Store) CreateRequest(ctx context.Context, r ExceptionRequest, by Actor) (id int64, err error) {
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
	err = tx.QueryRowContext(ctx, `
		INSERT INTO exception_requests (finding_id, kind, reason, requested_due, requested_by, requested_by_name, requested_at)
		VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		r.FindingID, r.Kind, r.Reason, r.RequestedDue, by.Subject, by.Name, now).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrPendingRequest
		}
		return 0, err
	}
	ev := map[string]any{"request": id, "kind": r.Kind, "reason": r.Reason, "by": by.Subject, "by_name": by.Label()}
	if r.RequestedDue != nil {
		ev["requested_due"] = *r.RequestedDue
	}
	if err = insertEvent(ctx, tx, r.FindingID, finding.EventExceptionAsked, sql.NullString{}, sql.NullString{}, ev, now); err != nil {
		return 0, err
	}
	if err = insertAudit(ctx, tx, by, "request.create", fmt.Sprint(id), ev, now); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

const requestColumns = `SELECT r.id, r.finding_id, r.kind, r.reason, r.requested_due, r.requested_by, r.requested_by_name,
	r.requested_at, r.status, r.decided_by, r.decided_by_name, r.decided_at, r.decision_note,
	f.vuln_id, f.service, f.environment, COALESCE(NULLIF(f.effective_severity, ''), f.severity)
	FROM exception_requests r JOIN findings f ON f.id = r.finding_id`

func scanRequest(sc scanner) (ExceptionRequest, error) {
	var (
		r       ExceptionRequest
		due     sql.NullString
		decided sql.NullString
	)
	if err := sc.Scan(&r.ID, &r.FindingID, &r.Kind, &r.Reason, &due, &r.RequestedBy, &r.RequestedByName,
		&r.RequestedAt, &r.Status, &r.DecidedBy, &r.DecidedByName, &decided, &r.DecisionNote,
		&r.VulnID, &r.Service, &r.Environment, &r.Severity); err != nil {
		return ExceptionRequest{}, err
	}
	if due.Valid {
		r.RequestedDue = &due.String
	}
	if decided.Valid {
		r.DecidedAt = &decided.String
	}
	return r, nil
}

// GetRequest returns one request.
func (s *Store) GetRequest(ctx context.Context, id int64) (ExceptionRequest, error) {
	return scanRequest(s.db.QueryRowContext(ctx, requestColumns+` WHERE r.id = ?`, id))
}

// RequestFilter narrows ListRequests. Zero values match everything.
type RequestFilter struct {
	FindingID int64
	Status    string
	Limit     int
}

// ListRequests returns requests, newest first.
func (s *Store) ListRequests(ctx context.Context, f RequestFilter) ([]ExceptionRequest, error) {
	var where []string
	var args []any
	if f.FindingID != 0 {
		where = append(where, "r.finding_id = ?")
		args = append(args, f.FindingID)
	}
	if f.Status != "" {
		where = append(where, "r.status = ?")
		args = append(args, f.Status)
	}
	q := requestColumns
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q += fmt.Sprintf(" ORDER BY r.requested_at DESC, r.id DESC LIMIT %d", limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExceptionRequest{}
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Decision closes a pending request.
type Decision struct {
	RequestID int64
	Status    string // approved, rejected or cancelled
	Note      string
	By        Actor
	// Evidence is added to the decision event (for example the
	// Dependency-Track analysis written for a risk acceptance).
	Evidence map[string]any
}

// DecideRequest closes a pending request and applies an approval:
// a risk acceptance moves the finding to risk_accepted, a due extension
// sets the finding's due date override at its current effective severity.
// It returns ErrNotPending when someone decided first.
func (s *Store) DecideRequest(ctx context.Context, d Decision) (err error) {
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
	var (
		findingID int64
		kind      string
		due       sql.NullString
	)
	err = tx.QueryRowContext(ctx, `
		UPDATE exception_requests SET status = ?, decided_by = ?, decided_by_name = ?, decided_at = ?, decision_note = ?
		WHERE id = ? AND status = 'pending'
		RETURNING finding_id, kind, requested_due`,
		d.Status, d.By.Subject, d.By.Name, now, d.Note, d.RequestID).Scan(&findingID, &kind, &due)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotPending
	}
	if err != nil {
		return err
	}

	ev := map[string]any{"request": d.RequestID, "kind": kind, "status": d.Status, "note": d.Note,
		"by": d.By.Subject, "by_name": d.By.Label()}
	for k, v := range d.Evidence {
		ev[k] = v
	}
	if err = insertEvent(ctx, tx, findingID, finding.EventExceptionDone, sql.NullString{}, sql.NullString{}, ev, now); err != nil {
		return err
	}
	if err = insertAudit(ctx, tx, d.By, "request."+d.Status, fmt.Sprint(d.RequestID), ev, now); err != nil {
		return err
	}

	if d.Status == RequestApproved {
		switch kind {
		case RequestRiskAcceptance:
			err = acceptRisk(ctx, tx, findingID, ev, now)
		case RequestDueExtension:
			err = extendDue(ctx, tx, findingID, due, ev, now)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func acceptRisk(ctx context.Context, tx *sql.Tx, id int64, ev map[string]any, now string) error {
	var from string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM findings WHERE id = ?`, id).Scan(&from); err != nil {
		return err
	}
	if !finding.CanTransition(finding.State(from), finding.StateRiskAccepted) {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET state = ?, updated_at = ? WHERE id = ?`,
		finding.StateRiskAccepted, now, id); err != nil {
		return err
	}
	ev = map[string]any{"reason": ReasonApproved, "request": ev["request"], "by": ev["by"], "by_name": ev["by_name"]}
	return insertEvent(ctx, tx, id, finding.EventStateChanged,
		sql.NullString{String: from, Valid: true}, sql.NullString{String: string(finding.StateRiskAccepted), Valid: true}, ev, now)
}

func extendDue(ctx context.Context, tx *sql.Tx, id int64, due sql.NullString, ev map[string]any, now string) error {
	if !due.Valid {
		return errors.New("due extension without a due date")
	}
	var (
		prevDue sql.NullString
		sev     string
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT due_at, COALESCE(NULLIF(effective_severity, ''), severity) FROM findings WHERE id = ?`, id).
		Scan(&prevDue, &sev); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE findings SET due_override = ?, due_override_severity = ?, due_at = ?,
		       reminded_due_soon_at = NULL, reminded_overdue_at = NULL, updated_at = ?
		WHERE id = ?`, due.String, sev, due.String, now, id); err != nil {
		return err
	}
	sla := map[string]any{"from_severity": sev, "to_severity": sev, "reasons": []string{}, "to_due": due.String,
		"extension": ev["request"], "by_name": ev["by_name"]}
	if prevDue.Valid {
		sla["from_due"] = prevDue.String
	}
	return insertEvent(ctx, tx, id, finding.EventSLAChanged, sql.NullString{}, sql.NullString{}, sla, now)
}

// ReasonApproved marks a state change made by an approved request.
const ReasonApproved = "request_approved"

// ClearDueOverride drops an approved due date, for example when the
// finding's severity rises above the one it was approved at.
func (s *Store) ClearDueOverride(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE findings SET due_override = NULL, due_override_severity = '' WHERE id = ?`, id)
	return err
}

// ---- settings and audit -----------------------------------------------

// SetSetting stores a setting changed by a person, with an audit entry.
// The audit entry records only the key: values may be secrets.
func (s *Store) SetSetting(ctx context.Context, key, value string, by Actor) (err error) {
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
	if value == "" {
		_, err = tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, key)
	} else {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, key, value, now)
	}
	if err != nil {
		return err
	}
	action := "setting.set"
	if value == "" {
		action = "setting.reset"
	}
	if err = insertAudit(ctx, tx, by, action, key, map[string]any{}, now); err != nil {
		return err
	}
	return tx.Commit()
}

// SettingUpdatedAt returns when a setting was last stored ("" when absent).
func (s *Store) SettingUpdatedAt(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT updated_at FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// AuditEntry is one line of the audit log.
type AuditEntry struct {
	ID        int64           `json:"id"`
	Actor     string          `json:"actor"`
	ActorName string          `json:"actor_name,omitempty"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	Detail    json.RawMessage `json:"detail"`
	At        string          `json:"at"`
}

// ListAudit returns the newest audit entries.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, actor, actor_name, action, target, detail, at FROM audit_log
		ORDER BY at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var (
			e      AuditEntry
			detail string
		)
		if err := rows.Scan(&e.ID, &e.Actor, &e.ActorName, &e.Action, &e.Target, &detail, &e.At); err != nil {
			return nil, err
		}
		e.Detail = json.RawMessage(detail)
		out = append(out, e)
	}
	return out, rows.Err()
}

func insertAudit(ctx context.Context, tx *sql.Tx, by Actor, action, target string, detail map[string]any, now string) error {
	d, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_log (actor, actor_name, action, target, detail, at) VALUES (?, ?, ?, ?, ?, ?)`,
		by.Subject, by.Name, action, target, string(d), now)
	return err
}

// expiresIn formats now+d the way the store keeps times.
func (s *Store) expiresIn(d time.Duration) string { return formatTime(s.now().Add(d)) }

// SessionExpiry returns the expiry time for a session or login starting now.
func (s *Store) SessionExpiry(d time.Duration) string { return s.expiresIn(d) }

// Settings people can change in the UI. A stored value replaces the
// environment variable; resetting it returns to the environment.
const (
	SettingWebhookToken = "webhook.token"        // PATCHLINE_WEBHOOK_TOKEN
	SettingGiteaSecret  = "webhook.gitea_secret" // PATCHLINE_GITEA_WEBHOOK_SECRET
)

// WebhookSecrets resolves the webhook token and the Git webhook secret:
// the stored value when there is one, else the environment's.
type WebhookSecrets struct {
	Store    *Store
	EnvToken string
	EnvGitea string
}

// Current returns the token and the Git webhook secret in effect.
func (w WebhookSecrets) Current(ctx context.Context) (token, gitea string, err error) {
	token, gitea = w.EnvToken, w.EnvGitea
	if w.Store == nil {
		return token, gitea, nil
	}
	if v, err := w.Store.Setting(ctx, SettingWebhookToken); err != nil {
		return "", "", err
	} else if v != "" {
		token = v
	}
	if v, err := w.Store.Setting(ctx, SettingGiteaSecret); err != nil {
		return "", "", err
	} else if v != "" {
		gitea = v
	}
	return token, gitea, nil
}
