package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
)

var (
	alice = Actor{Subject: "u-alice", Name: "Alice"}
	bob   = Actor{Subject: "u-bob", Name: "Bob"}
)

func accessFinding(t *testing.T, s *Store) int64 {
	t.Helper()
	id, _, err := s.UpsertFinding(context.Background(), finding.Observation{Service: "svc", Environment: "main",
		ComponentRef: "pkg:npm/x@1", VulnID: "CVE-1", Severity: finding.SeverityHigh,
		DTProjectUUID: "p", DTComponentUUID: "c", DTVulnerabilityUUID: "v"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func eventKinds(t *testing.T, s *Store, id int64) []string {
	t.Helper()
	events, err := s.FindingEvents(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range events {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

func TestSessions(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.CreateSession(ctx, Session{IDHash: "h1", Subject: "u", Groups: []string{"a"}, CSRF: "c",
		CreatedAt: s.SessionExpiry(0), ExpiresAt: s.SessionExpiry(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSession(ctx, "h1")
	if err != nil || got.Subject != "u" || len(got.Groups) != 1 || got.CSRF != "c" {
		t.Fatalf("session = %+v, %v", got, err)
	}
	_ = s.CreateSession(ctx, Session{IDHash: "old", Subject: "u", CSRF: "c", CreatedAt: s.SessionExpiry(-2 * time.Hour), ExpiresAt: s.SessionExpiry(-time.Hour)})
	if _, err := s.GetSession(ctx, "old"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expired session: %v", err)
	}
	if err := s.DeleteSession(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession(ctx, "h1"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("deleted session: %v", err)
	}

	if err := s.SaveAuthState(ctx, AuthState{State: "st", Nonce: "n", Verifier: "v", Next: "/x", ExpiresAt: s.SessionExpiry(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if a, err := s.TakeAuthState(ctx, "st"); err != nil || a.Nonce != "n" || a.Next != "/x" {
		t.Fatalf("take = %+v %v", a, err)
	}
	if _, err := s.TakeAuthState(ctx, "st"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("second take: %v", err)
	}
}

func TestAssign(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id := accessFinding(t, s)
	if changed, err := s.AssignFinding(ctx, id, " carol@example.com ", alice); err != nil || !changed {
		t.Fatalf("assign: %v %v", changed, err)
	}
	if changed, _ := s.AssignFinding(ctx, id, "carol@example.com", alice); changed {
		t.Error("same assignee counted as a change")
	}
	mine, _ := s.ListFindings(ctx, FindingFilter{Assignee: "carol@example.com"})
	if len(mine) != 1 || mine[0].Assignee != "carol@example.com" {
		t.Fatalf("filter = %+v", mine)
	}
	if kinds := eventKinds(t, s, id); kinds[len(kinds)-1] != finding.EventAssigned {
		t.Errorf("events = %v", kinds)
	}
	audit, _ := s.ListAudit(ctx, 10)
	if len(audit) != 1 || audit[0].Action != "finding.assign" || audit[0].ActorName != "Alice" {
		t.Errorf("audit = %+v", audit)
	}
}

func TestRiskAcceptance(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id := accessFinding(t, s)

	rid, err := s.CreateRequest(ctx, ExceptionRequest{FindingID: id, Kind: RequestRiskAcceptance, Reason: "WAF rule in place"}, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRequest(ctx, ExceptionRequest{FindingID: id, Kind: RequestRiskAcceptance, Reason: "again"}, alice); !errors.Is(err, ErrPendingRequest) {
		t.Fatalf("duplicate pending: %v", err)
	}
	pending, _ := s.ListRequests(ctx, RequestFilter{Status: RequestPending})
	if len(pending) != 1 || pending[0].VulnID != "CVE-1" || pending[0].RequestedByName != "Alice" {
		t.Fatalf("pending = %+v", pending)
	}

	if err := s.DecideRequest(ctx, Decision{RequestID: rid, Status: RequestApproved, Note: "ok until Q1", By: bob,
		Evidence: map[string]any{"dependency_track": "suppressed"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.DecideRequest(ctx, Decision{RequestID: rid, Status: RequestRejected, By: bob}); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second decision: %v", err)
	}
	f, _ := s.GetFinding(ctx, id)
	if f.State != string(finding.StateRiskAccepted) {
		t.Fatalf("state = %s", f.State)
	}
	r, _ := s.GetRequest(ctx, rid)
	if r.Status != RequestApproved || r.DecidedBy != "u-bob" || r.DecisionNote != "ok until Q1" || r.DecidedAt == nil {
		t.Fatalf("request = %+v", r)
	}
	kinds := eventKinds(t, s, id)
	want := []string{finding.EventDetected, finding.EventExceptionAsked, finding.EventExceptionDone, finding.EventStateChanged}
	if len(kinds) != len(want) {
		t.Fatalf("events = %v", kinds)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("events = %v, want %v", kinds, want)
		}
	}
	// A new request may follow once the first one is closed.
	if _, err := s.CreateRequest(ctx, ExceptionRequest{FindingID: id, Kind: RequestRiskAcceptance, Reason: "x"}, alice); err != nil {
		t.Errorf("after decision: %v", err)
	}
}

func TestDueExtension(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id := accessFinding(t, s)
	open, _ := s.OpenFindingsForSLA(ctx)
	due := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	_ = s.UpdateSLA(ctx, SLAUpdate{FindingID: id, EffectiveSeverity: "high", Due: &due, Silent: true}, open[0].Finding)

	later := "2026-12-31T23:59:59.999Z"
	rid, err := s.CreateRequest(ctx, ExceptionRequest{FindingID: id, Kind: RequestDueExtension, Reason: "vendor fix in December", RequestedDue: &later}, alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DecideRequest(ctx, Decision{RequestID: rid, Status: RequestApproved, By: bob}); err != nil {
		t.Fatal(err)
	}
	f, _ := s.GetFinding(ctx, id)
	if f.DueAt == nil || *f.DueAt != later || f.DueOverride == nil || *f.DueOverride != later || f.DueOverrideSeverity != "high" {
		t.Fatalf("finding = %+v", f)
	}
	if f.State == string(finding.StateRiskAccepted) {
		t.Error("an extension must not close the finding")
	}
	events, _ := s.FindingEvents(ctx, id)
	last := events[len(events)-1]
	var ev map[string]any
	_ = json.Unmarshal(last.Evidence, &ev)
	if last.Kind != finding.EventSLAChanged || ev["to_due"] != later || ev["from_due"] != "2026-11-05T00:00:00.000Z" {
		t.Fatalf("last event = %s %s", last.Kind, last.Evidence)
	}

	// A regression starts over: the extension no longer applies.
	_, _ = s.ResolveMissing(ctx, "p", nil, map[string]any{})
	_, _, _ = s.UpsertFinding(ctx, finding.Observation{Service: "svc", Environment: "main", ComponentRef: "pkg:npm/x@1",
		VulnID: "CVE-1", Severity: finding.SeverityHigh, DTProjectUUID: "p"}, nil)
	f, _ = s.GetFinding(ctx, id)
	if f.State != string(finding.StateReopened) || f.DueOverride != nil {
		t.Fatalf("after reopen: %+v", f)
	}
}

func TestRejectAndCancel(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id := accessFinding(t, s)
	later := "2026-12-31T23:59:59.999Z"
	r1, _ := s.CreateRequest(ctx, ExceptionRequest{FindingID: id, Kind: RequestDueExtension, Reason: "r", RequestedDue: &later}, alice)
	if err := s.DecideRequest(ctx, Decision{RequestID: r1, Status: RequestRejected, Note: "fix it", By: bob}); err != nil {
		t.Fatal(err)
	}
	r2, _ := s.CreateRequest(ctx, ExceptionRequest{FindingID: id, Kind: RequestRiskAcceptance, Reason: "r"}, alice)
	if err := s.DecideRequest(ctx, Decision{RequestID: r2, Status: RequestCancelled, By: alice}); err != nil {
		t.Fatal(err)
	}
	f, _ := s.GetFinding(ctx, id)
	if f.State != string(finding.StateNew) || f.DueOverride != nil {
		t.Fatalf("finding changed by a rejection: %+v", f)
	}
	all, _ := s.ListRequests(ctx, RequestFilter{FindingID: id})
	if len(all) != 2 || all[0].Status != RequestCancelled || all[1].Status != RequestRejected {
		t.Fatalf("requests = %+v", all)
	}
}

func TestWebhookSecrets(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	w := WebhookSecrets{Store: s, EnvToken: "env-token", EnvGitea: ""}
	if tok, gitea, _ := w.Current(ctx); tok != "env-token" || gitea != "" {
		t.Fatalf("env: %q %q", tok, gitea)
	}
	if err := s.SetSetting(ctx, SettingWebhookToken, "ui-token-0123456789", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, SettingGiteaSecret, "ui-gitea-0123456789", alice); err != nil {
		t.Fatal(err)
	}
	if tok, gitea, _ := w.Current(ctx); tok != "ui-token-0123456789" || gitea != "ui-gitea-0123456789" {
		t.Fatalf("ui: %q %q", tok, gitea)
	}
	if err := s.SetSetting(ctx, SettingWebhookToken, "", alice); err != nil {
		t.Fatal(err)
	}
	if tok, _, _ := w.Current(ctx); tok != "env-token" {
		t.Fatalf("reset: %q", tok)
	}
	audit, _ := s.ListAudit(ctx, 10)
	if len(audit) != 3 || audit[0].Action != "setting.reset" || string(audit[1].Detail) != "{}" {
		t.Fatalf("audit = %+v (values must not be logged)", audit)
	}
}
