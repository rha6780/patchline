// Package app carries out the changes people make to findings: assigning
// them, requesting exceptions and deciding requests. The web pages and the
// API both call it, so permissions, validation and the write-back to the
// tools that keep their own analysis (Dependency-Track) are the same
// whichever way a change arrives. Every
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
	"github.com/rha6780/patchline/internal/source"
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
	FindingRefs(ctx context.Context, findingID int64) ([]finding.Ref, error)
	CurrentRefs(ctx context.Context, findingID int64) ([]finding.Ref, error)
}

// Service applies changes.
type Service struct {
	Store Store
	// Sources' decision writers receive approved decisions on the findings
	// their tools report.
	Sources *source.Registry
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
		// A decision on a finding a tool with its own analysis reports is
		// written there; one on a finding only Patchline reports stays in
		// Patchline.
		r, err := s.Recorders(ctx, f)
		if err != nil {
			return 0, err
		}
		if !r.Ready {
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
// finding a tool with its own analysis reports writes it there first, and
// approves nothing if that fails.
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
		targets, err := s.targets(ctx, f)
		if err != nil {
			return req, err
		}
		recorded := []string{}
		for _, t := range targets {
			if err := s.write(ctx, t, req, p); err != nil {
				return req, &Error{Code: "dt_write", Err: err}
			}
			recorded = append(recorded, t.w.Name())
		}
		if len(recorded) == 0 {
			recorded = append(recorded, "patchline")
		}
		d.Evidence = map[string]any{"recorded_in": strings.Join(recorded, ",")}
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

// Recorders are the tools that keep decisions about a finding.
type Recorders struct {
	// Tools names them by source; empty when only Patchline does.
	Tools []string
	// Ready is false when one of them cannot be written to now, so
	// decisions on the finding cannot be approved.
	Ready bool
}

// Recorders says where a decision on f is recorded besides Patchline.
func (s *Service) Recorders(ctx context.Context, f store.Finding) (Recorders, error) {
	targets, err := s.targets(ctx, f)
	if err != nil {
		return Recorders{}, err
	}
	r := Recorders{Ready: true}
	for _, t := range targets {
		r.Tools = append(r.Tools, t.w.Name())
		r.Ready = r.Ready && t.w.Ready()
	}
	return r, nil
}

// target is a tool to write a decision to, and the refs to write it as.
type target struct {
	w    source.DecisionWriter
	refs []finding.Ref
}

// targets returns the decision writers keeping refs of f. A writer gets
// the refs of the projects reporting f now; only when none does, every ref
// it keeps (a component removed there may be gone with its analysis).
func (s *Service) targets(ctx context.Context, f store.Finding) ([]target, error) {
	all, err := s.Store.FindingRefs(ctx, f.ID)
	if err != nil {
		return nil, err
	}
	current, err := s.Store.CurrentRefs(ctx, f.ID)
	if err != nil {
		return nil, err
	}
	kept := func(refs []finding.Ref) map[string][]finding.Ref {
		out := map[string][]finding.Ref{}
		for _, ref := range refs {
			if w, ok := s.Sources.DecisionWriter(ref.Source); ok && w.Keeps(ref) {
				out[ref.Source] = append(out[ref.Source], ref)
			}
		}
		return out
	}
	now, ever := kept(current), kept(all)
	var out []target
	for _, ref := range all { // in source order, once per source
		refs, ok := ever[ref.Source]
		if !ok {
			continue
		}
		delete(ever, ref.Source)
		if len(now[ref.Source]) > 0 {
			refs = now[ref.Source]
		}
		w, _ := s.Sources.DecisionWriter(ref.Source)
		out = append(out, target{w: w, refs: refs})
	}
	return out, nil
}

// write records the decision as every ref of the target.
func (s *Service) write(ctx context.Context, t target, req store.ExceptionRequest, p *auth.Principal) error {
	d := source.Decision{RequestID: req.ID, Kind: req.Kind, Justification: req.Justification, Reason: req.Reason,
		RequestedBy: labelOr(req.RequestedByName, req.RequestedBy), ApprovedBy: p.Label()}
	for _, ref := range t.refs {
		if err := t.w.WriteDecision(ctx, ref, d); err != nil {
			return fmt.Errorf("%s project %s: %w", t.w.Name(), ref.Project, err)
		}
	}
	return nil
}

func labelOr(name, subject string) string {
	if name != "" {
		return name
	}
	return subject
}
