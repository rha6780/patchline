package app_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/app"
	"github.com/rha6780/patchline/internal/auth"
	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/source"
	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/store"
)

type fakeDT struct {
	got []dependencytrack.AnalysisUpdate
	err error
}

func (f *fakeDT) SetAnalysis(_ context.Context, a dependencytrack.AnalysisUpdate) error {
	f.got = append(f.got, a)
	return f.err
}

func person(subject string, perms ...auth.Permission) *auth.Principal {
	set := auth.Set{auth.FindingsRead: true}
	for _, p := range perms {
		set[p] = true
	}
	return &auth.Principal{Authenticated: true, Subject: subject, Name: subject, Perms: set}
}

func setup(t *testing.T, dt dependencytrack.AnalysisWriter) (*app.Service, *store.Store, int64, int64, *int) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	obs := finding.Observation{Service: "storefront", Registered: true, Environment: "main",
		ComponentRef: "pkg:npm/lodash@4.17.20", ComponentName: "lodash", ComponentVersion: "4.17.20",
		VulnID: "CVE-2021-23337", Severity: finding.SeverityHigh}
	native, _, err := st.UpsertFinding(ctx, obs, nil)
	if err != nil {
		t.Fatal(err)
	}
	obs.VulnID, obs.DTProjectUUID, obs.DTComponentUUID, obs.DTVulnerabilityUUID = "CVE-2020-8203", "p", "c", "v"
	inDT, _, err := st.UpsertFinding(ctx, obs, nil)
	if err != nil {
		t.Fatal(err)
	}
	changes := 0
	adapter := &dependencytrack.Adapter{}
	if dt != nil {
		adapter.Analyses = dt
	}
	svc := &app.Service{Store: st, Sources: source.NewRegistry(adapter), OnChange: func() { changes++ }, Now: time.Now}
	return svc, st, native, inDT, &changes
}

func code(err error) string {
	var e *app.Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return "unexpected: " + err.Error()
	}
	return ""
}

func TestAssign(t *testing.T) {
	svc, st, id, _, changes := setup(t, nil)
	ctx := context.Background()
	if err := svc.Assign(ctx, person("viewer"), id, "a@example.com"); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("viewer: %v", err)
	}
	dev := person("dev", auth.FindingsAssign)
	if err := svc.Assign(ctx, dev, 999, "a@example.com"); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing finding: %v", err)
	}
	if err := svc.Assign(ctx, dev, id, string(make([]byte, 300))); code(err) != "assignee" {
		t.Fatalf("long assignee: %v", err)
	}
	if err := svc.Assign(ctx, dev, id, " a@example.com "); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFinding(ctx, id); f.Assignee != "a@example.com" || *changes != 1 {
		t.Fatalf("assignee %q, changes %d", f.Assignee, *changes)
	}
	_ = svc.Assign(ctx, dev, id, "a@example.com") // unchanged: no wake-up
	if *changes != 1 {
		t.Fatalf("changes = %d", *changes)
	}
}

func TestRequestValidation(t *testing.T) {
	svc, _, id, inDT, _ := setup(t, nil)
	ctx := context.Background()
	dev := person("dev", auth.ExceptionsRequest)
	tomorrow := time.Now().Add(48 * time.Hour).UTC().Format("2006-01-02")
	for _, tc := range []struct {
		name string
		p    *auth.Principal
		in   app.RequestInput
		want string
	}{
		{"no permission", person("viewer"), app.RequestInput{FindingID: id, Kind: "risk_acceptance", Reason: "r"}, "forbidden"},
		{"missing", dev, app.RequestInput{FindingID: 999, Kind: "risk_acceptance", Reason: "r"}, "not_found"},
		{"no reason", dev, app.RequestInput{FindingID: id, Kind: "risk_acceptance", Reason: "  "}, "reason"},
		{"unknown kind", dev, app.RequestInput{FindingID: id, Kind: "nope", Reason: "r"}, "kind"},
		{"no justification", dev, app.RequestInput{FindingID: id, Kind: "not_affected", Reason: "r"}, "justification"},
		{"bad date", dev, app.RequestInput{FindingID: id, Kind: "due_extension", Reason: "r", Due: "soon"}, "due"},
		{"past date", dev, app.RequestInput{FindingID: id, Kind: "due_extension", Reason: "r", Due: "2020-01-01"}, "due_earlier"},
		{"dt finding without dt", dev, app.RequestInput{FindingID: inDT, Kind: "false_positive", Reason: "r"}, "no_dt"},
		{"ok", dev, app.RequestInput{FindingID: id, Kind: "due_extension", Reason: "r", Due: tomorrow}, ""},
		{"pending", dev, app.RequestInput{FindingID: id, Kind: "due_extension", Reason: "r", Due: tomorrow}, "pending"},
	} {
		if _, err := svc.Request(ctx, tc.p, tc.in); code(err) != tc.want {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestDecide(t *testing.T) {
	dt := &fakeDT{}
	svc, st, native, inDT, _ := setup(t, dt)
	ctx := context.Background()
	dev := person("dev", auth.ExceptionsRequest, auth.ExceptionsApprove)
	lead := person("lead", auth.ExceptionsApprove)

	rid, err := svc.Request(ctx, dev, app.RequestInput{FindingID: native, Kind: "not_affected", Reason: "not reachable",
		Justification: "code_not_reachable"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(ctx, dev, rid, app.Approve, ""); code(err) != "own_request" {
		t.Fatalf("own request: %v", err)
	}
	if _, err := svc.Decide(ctx, person("viewer"), rid, app.Approve, ""); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("viewer: %v", err)
	}
	if _, err := svc.Decide(ctx, lead, rid, app.Cancel, ""); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("cancel by someone else: %v", err)
	}
	req, err := svc.Decide(ctx, lead, rid, app.Approve, "ok")
	if err != nil || req.FindingID != native {
		t.Fatalf("approve: %+v %v", req, err)
	}
	if f, _ := st.GetFinding(ctx, native); f.State != string(finding.StateNotAffected) || len(dt.got) != 0 {
		t.Fatalf("native finding: state %s, dt writes %d", f.State, len(dt.got))
	}
	if _, err := svc.Decide(ctx, lead, rid, app.Reject, ""); code(err) != "not_pending" {
		t.Fatalf("decided twice: %v", err)
	}

	// A Dependency-Track finding is written there first; a failed write
	// approves nothing.
	rid, _ = svc.Request(ctx, dev, app.RequestInput{FindingID: inDT, Kind: "risk_acceptance", Reason: "legacy\nservice"})
	dt.err = errors.New("403")
	if _, err := svc.Decide(ctx, lead, rid, app.Approve, ""); code(err) != "dt_write" {
		t.Fatalf("dt failure: %v", err)
	}
	if f, _ := st.GetFinding(ctx, inDT); f.State == string(finding.StateRiskAccepted) {
		t.Fatal("approved despite the failed write")
	}
	dt.err = nil
	if _, err := svc.Decide(ctx, lead, rid, app.Approve, ""); err != nil {
		t.Fatal(err)
	}
	a := dt.got[len(dt.got)-1]
	if a.State != "EXPLOITABLE" || a.Response != "WILL_NOT_FIX" || !a.Suppressed || a.Details != "legacy service" {
		t.Fatalf("analysis = %+v", a)
	}
	if f, _ := st.GetFinding(ctx, inDT); f.State != string(finding.StateRiskAccepted) {
		t.Fatalf("state = %s", f.State)
	}

}

// TestDecisionTargets: a finding two Dependency-Track projects report is
// written to both; once a project stops reporting it, only to the other.
func TestDecisionTargets(t *testing.T) {
	dt := &fakeDT{}
	svc, st, native, inDT, _ := setup(t, dt)
	ctx := context.Background()
	f, _ := st.GetFinding(ctx, inDT)
	obs := finding.Observation{Service: f.Service, Registered: true, Environment: f.Environment, ComponentRef: f.ComponentRef,
		VulnID: f.VulnID, Severity: finding.SeverityHigh, DTProjectUUID: "p2", DTComponentUUID: "c2", DTVulnerabilityUUID: "v"}
	if _, _, err := st.UpsertFinding(ctx, obs, nil); err != nil {
		t.Fatal(err)
	}
	if r, _ := svc.Recorders(ctx, f); len(r.Tools) != 1 || r.Tools[0] != dependencytrack.Name || !r.Ready {
		t.Fatalf("recorders = %+v", r)
	}
	if r, _ := svc.Recorders(ctx, store.Finding{ID: native}); len(r.Tools) != 0 || !r.Ready {
		t.Fatalf("native recorders = %+v", r)
	}

	dev := person("dev", auth.ExceptionsRequest)
	lead := person("lead", auth.ExceptionsApprove)
	approve := func() {
		t.Helper()
		rid, err := svc.Request(ctx, dev, app.RequestInput{FindingID: inDT, Kind: "false_positive", Reason: "r"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Decide(ctx, lead, rid, app.Approve, ""); err != nil {
			t.Fatal(err)
		}
	}
	approve()
	if len(dt.got) != 2 || dt.got[0].ProjectUUID != "p" || dt.got[1].ProjectUUID != "p2" || dt.got[1].ComponentUUID != "c2" {
		t.Fatalf("writes = %+v", dt.got)
	}

	// p2 no longer reports it; reopen the finding through p.
	if _, err := st.ResolveMissingIn(ctx, dependencytrack.Name, "p2", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyStateByRef(ctx, finding.Ref{Source: dependencytrack.Name, Project: "p", Component: "c", Vuln: "v"},
		finding.StateInProgress, nil); err != nil {
		t.Fatal(err)
	}
	dt.got = nil
	approve()
	if len(dt.got) != 1 || dt.got[0].ProjectUUID != "p" {
		t.Fatalf("writes after p2 stopped reporting = %+v", dt.got)
	}
}

func TestCancel(t *testing.T) {
	svc, st, id, _, _ := setup(t, nil)
	ctx := context.Background()
	dev := person("dev", auth.ExceptionsRequest)
	rid, err := svc.Request(ctx, dev, app.RequestInput{FindingID: id, Kind: "false_positive", Reason: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(ctx, dev, rid, "maybe", ""); code(err) != "action" {
		t.Fatalf("unknown action: %v", err)
	}
	if _, err := svc.Decide(ctx, dev, rid, app.Cancel, ""); err != nil {
		t.Fatal(err)
	}
	if req, _ := st.GetRequest(ctx, rid); req.Status != store.RequestCancelled {
		t.Fatalf("status = %s", req.Status)
	}
	if _, err := svc.Decide(ctx, dev, 999, app.Cancel, ""); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("missing request: %v", err)
	}
}
