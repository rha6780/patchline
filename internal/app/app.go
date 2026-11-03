// Package app carries out the changes people make to findings: assigning
// them, requesting exceptions and deciding requests. The web pages and the
// API both call it, so permissions, validation and the write-back to
// Dependency-Track are the same whichever way a change arrives. Every
// change is recorded on the finding's timeline and in the audit log by the
// store.
package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/auth"
	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/store"
)

// MaxReason bounds request reasons and decision notes.
const MaxReason = 2000

// MaxAssignee bounds an assignee (an email address).
const MaxAssignee = 254

// Store is the persistence the service needs.
type Store interface {
	GetFinding(ctx context.Context, id int64) (store.Finding, error)
	AssignFinding(ctx context.Context, id int64, assignee string, by store.Actor) (bool, error)
	CreateRequest(ctx context.Context, r store.ExceptionRequest, by store.Actor) (int64, error)
	GetRequest(ctx context.Context, id int64) (store.ExceptionRequest, error)
	DecideRequest(ctx context.Context, d store.Decision) error
}

// AnalysisWriter records analysis decisions in Dependency-Track.
type AnalysisWriter interface {
	SetAnalysis(ctx context.Context, a dependencytrack.AnalysisUpdate) error
}

// Service applies changes.
type Service struct {
	Store Store
	// DT, when set, receives decisions on findings Dependency-Track reports.
	DT AnalysisWriter
	// OnChange is called after a change (to wake the SLA job and the
	// notifier).
	OnChange func()
	Now      func() time.Time
}

// Errors. A refused change is an *Error; ErrNotFound and ErrForbidden
// are wrapped in one too.
var (
	ErrNotFound  = errors.New("not found")
	ErrForbidden = errors.New("not permitted")
)

// Error is a change that was refused. Code names the reason; the web pages
// show it as the message ui.err.<code>.
type Error struct {
	Code string
	Err  error // ErrNotFound, ErrForbidden or the cause, if any
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Err.Error()
	}
	return e.Code
}

func (e *Error) Unwrap() error { return e.Err }

func refuse(code string) error { return &Error{Code: code} }

var (
	errForbidden = &Error{Code: "forbidden", Err: ErrForbidden}
	errNotFound  = &Error{Code: "not_found", Err: ErrNotFound}
)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) changed() {
	if s.OnChange != nil {
		s.OnChange()
	}
}

func (s *Service) finding(ctx context.Context, id int64) (store.Finding, error) {
	f, err := s.Store.GetFinding(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return store.Finding{}, errNotFound
	}
	return f, err
}

// Assign sets the person working on a finding; "" clears it.
func (s *Service) Assign(ctx context.Context, p *auth.Principal, findingID int64, assignee string) error {
	if !p.Can(auth.FindingsAssign) {
		return errForbidden
	}
	if _, err := s.finding(ctx, findingID); err != nil {
		return err
	}
	assignee = strings.TrimSpace(assignee)
	if len(assignee) > MaxAssignee {
		return refuse("assignee")
	}
	changed, err := s.Store.AssignFinding(ctx, findingID, assignee, p.Actor())
	if err != nil {
		return err
	}
	if changed {
		s.changed()
	}
	return nil
}

// RequestInput is an exception request.
type RequestInput struct {
	FindingID int64
	// Kind is risk_acceptance, not_affected, false_positive or
	// due_extension.
	Kind   string
	Reason string
	// Justification is required for not_affected (a CycloneDX
	// justification such as code_not_reachable).
	Justification string
	// Due is the requested due date (YYYY-MM-DD) for due_extension.
	Due string
}

// Request asks an approver for an exception and returns the request's id.
func (s *Service) Request(ctx context.Context, p *auth.Principal, in RequestInput) (int64, error) {
	if !p.Can(auth.ExceptionsRequest) {
		return 0, errForbidden
	}
	f, err := s.finding(ctx, in.FindingID)
	if err != nil {
		return 0, err
	}
	if !finding.State(f.State).Open() {
		return 0, refuse("closed")
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" || len(reason) > MaxReason {
		return 0, refuse("reason")
	}
	req := store.ExceptionRequest{FindingID: f.ID, Kind: in.Kind, Reason: reason}
	switch in.Kind {
	case store.RequestRiskAcceptance, store.RequestFalsePositive, store.RequestNotAffected:
		if in.Kind == store.RequestNotAffected {
			if !slices.Contains(store.Justifications, in.Justification) {
				return 0, refuse("justification")
			}
			req.Justification = in.Justification
		}
		// A decision on a Dependency-Track finding is written there; one on
		// a finding only Patchline reports stays in Patchline.
		if InDT(f) && s.DT == nil {
			return 0, refuse("no_dt")
		}
	case store.RequestDueExtension:
		day, err := time.Parse("2006-01-02", in.Due)
		if err != nil {
			return 0, refuse("due")
		}
		// The end of the chosen day, so "due 2026-12-01" means all of it.
		due := day.Add(24*time.Hour - time.Millisecond).UTC()
		floor := s.now()
		if f.DueAt != nil {
			if t, err := time.Parse(store.TimeLayout, *f.DueAt); err == nil && t.After(floor) {
				floor = t
			}
		}
		if !due.After(floor) {
			return 0, refuse("due_earlier")
		}
		d := store.FormatTime(due)
		req.RequestedDue = &d
	default:
		return 0, refuse("kind")
	}
	id, err := s.Store.CreateRequest(ctx, req, p.Actor())
	if errors.Is(err, store.ErrPendingRequest) {
		return 0, refuse("pending")
	}
	if err != nil {
		return 0, err
	}
	s.changed()
	return id, nil
}

// Decision actions.
const (
	Approve = "approve"
	Reject  = "reject"
	Cancel  = "cancel"
)

// Decide approves, rejects or withdraws a request and returns it as it
// was before the decision (also on error, once it was found, so callers
// can point back to its finding). Approvers cannot decide their own
// requests; only the requester can withdraw one. Approving a decision on a
// finding Dependency-Track reports writes it there first, and approves
// nothing if that fails.
func (s *Service) Decide(ctx context.Context, p *auth.Principal, requestID int64, action, note string) (store.ExceptionRequest, error) {
	req, err := s.Store.GetRequest(ctx, requestID)
	if errors.Is(err, sql.ErrNoRows) {
		return store.ExceptionRequest{}, errNotFound
	}
	if err != nil {
		return store.ExceptionRequest{}, err
	}
	note = strings.TrimSpace(note)
	if len(note) > MaxReason {
		return req, refuse("reason")
	}
	d := store.Decision{RequestID: requestID, Note: note, By: p.Actor()}
	switch action {
	case Approve, Reject:
		if !p.Can(auth.ExceptionsApprove) {
			return req, errForbidden
		}
		if req.RequestedBy == p.Subject {
			return req, refuse("own_request")
		}
		d.Status = store.RequestRejected
		if action == Approve {
			d.Status = store.RequestApproved
		}
	case Cancel:
		if req.RequestedBy != p.Subject || !p.Authenticated {
			return req, errForbidden
		}
		d.Status = store.RequestCancelled
	default:
		return req, refuse("action")
	}
	if req.Status != store.RequestPending {
		return req, refuse("not_pending")
	}

	if d.Status == store.RequestApproved && IsDecision(req.Kind) {
		f, err := s.Store.GetFinding(ctx, req.FindingID)
		if err != nil {
			return req, err
		}
		if InDT(f) {
			if err := s.writeToDT(ctx, f, req, p); err != nil {
				return req, &Error{Code: "dt_write", Err: err}
			}
			d.Evidence = map[string]any{"recorded_in": "dependency-track"}
		} else {
			d.Evidence = map[string]any{"recorded_in": "patchline"}
		}
	}
	if err := s.Store.DecideRequest(ctx, d); errors.Is(err, store.ErrNotPending) {
		return req, refuse("not_pending")
	} else if err != nil {
		return req, err
	}
	s.changed()
	return req, nil
}

// IsDecision reports whether a request kind closes the finding with an
// analysis decision.
func IsDecision(kind string) bool {
	switch kind {
	case store.RequestRiskAcceptance, store.RequestNotAffected, store.RequestFalsePositive:
		return true
	}
	return false
}

// InDT reports whether Dependency-Track knows the finding, so decisions
// about it belong there.
func InDT(f store.Finding) bool {
	return f.DTProjectUUID != "" && f.DTComponentUUID != "" && f.DTVulnerabilityUUID != ""
}

// writeToDT records the decision in Dependency-Track, so it lives where
// the analysis lives. The PROJECT_AUDIT_CHANGE that follows is a no-op:
// the finding is already closed.
func (s *Service) writeToDT(ctx context.Context, f store.Finding, req store.ExceptionRequest, p *auth.Principal) error {
	if s.DT == nil {
		return errors.New("dependency-track is not configured (PATCHLINE_DT_URL, PATCHLINE_DT_API_KEY)")
	}
	reason := oneLine(req.Reason)
	a := dependencytrack.AnalysisUpdate{
		ProjectUUID: f.DTProjectUUID, ComponentUUID: f.DTComponentUUID, VulnerabilityUUID: f.DTVulnerabilityUUID,
		Justification: "NOT_SET", Response: "NOT_SET", Details: reason,
	}
	what := ""
	switch req.Kind {
	case store.RequestRiskAcceptance:
		a.State, a.Response, a.Suppressed, what = "EXPLOITABLE", "WILL_NOT_FIX", true, "Risk accepted"
	case store.RequestNotAffected:
		a.State, a.Justification, what = "NOT_AFFECTED", strings.ToUpper(req.Justification), "Not affected ("+req.Justification+")"
	case store.RequestFalsePositive:
		a.State, what = "FALSE_POSITIVE", "False positive"
	}
	a.Comment = fmt.Sprintf("%s in Patchline (request #%d): requested by %s, approved by %s. %s",
		what, req.ID, labelOr(req.RequestedByName, req.RequestedBy), p.Label(), reason)
	return s.DT.SetAnalysis(ctx, a)
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func labelOr(name, subject string) string {
	if name != "" {
		return name
	}
	return subject
}
