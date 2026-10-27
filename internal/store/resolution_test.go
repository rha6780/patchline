package store

import (
	"context"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
)

func TestResolveMissingAndReopen(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	mk := func(ref string) finding.Observation {
		return finding.Observation{Service: "svc", Registered: true, Environment: "main", ComponentRef: ref,
			VulnID: "CVE-1", Severity: finding.SeverityHigh, DTProjectUUID: "p1", DTComponentUUID: "c-" + ref, DTVulnerabilityUUID: "v"}
	}
	kept, _, _ := s.UpsertFinding(ctx, mk("pkg:npm/kept@1"), nil)
	gone, _, _ := s.UpsertFinding(ctx, mk("pkg:npm/gone@1"), nil)
	accepted, _, _ := s.UpsertFinding(ctx, mk("pkg:npm/accepted@1"), nil)
	_, _ = s.ApplyState(ctx, DTKey{"p1", "c-pkg:npm/accepted@1", "v"}, finding.StateRiskAccepted, nil)
	other := mk("pkg:npm/other@1")
	other.DTProjectUUID = "p2"
	otherID, _, _ := s.UpsertFinding(ctx, other, nil)

	resolved, err := s.ResolveMissing(ctx, "p1", []int64{kept}, map[string]any{"commit": "abc1234"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0] != gone {
		t.Fatalf("resolved = %v, want [%d]", resolved, gone)
	}

	state := func(id int64) (string, *string) {
		f, err := s.GetFinding(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return f.State, f.ResolvedAt
	}
	if st, at := state(gone); st != "resolved" || at == nil {
		t.Errorf("gone: %s %v", st, at)
	}
	for id, want := range map[int64]string{kept: "new", accepted: "risk_accepted", otherID: "new"} {
		if st, _ := state(id); st != want {
			t.Errorf("finding %d: %s, want %s", id, st, want)
		}
	}

	// Resolving again is a no-op.
	if again, _ := s.ResolveMissing(ctx, "p1", []int64{kept}, nil); len(again) != 0 {
		t.Errorf("second resolve = %v", again)
	}

	// Seen again: reopened, resolved_at cleared.
	if _, created, err := s.UpsertFinding(ctx, mk("pkg:npm/gone@1"), map[string]any{"inbox_id": 9}); err != nil || created {
		t.Fatalf("re-upsert: created=%v err=%v", created, err)
	}
	if st, at := state(gone); st != "reopened" || at != nil {
		t.Errorf("after regression: %s %v", st, at)
	}

	events, _ := s.FindingEvents(ctx, gone)
	last := events[len(events)-1]
	if last.Kind != finding.EventStateChanged || *last.FromState != "resolved" || *last.ToState != "reopened" {
		t.Errorf("last event = %+v", last)
	}
	resolvedEv := events[len(events)-2]
	if string(resolvedEv.Evidence) != `{"reason":"absent_from_latest_bom","snapshot":{"commit":"abc1234"}}` {
		t.Errorf("resolution evidence = %s", resolvedEv.Evidence)
	}
}

func TestInsertInboxAt(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	clock := time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }

	if _, ok, err := s.InsertInboxAt(ctx, "dependencytrack", "reconcile", "k", []byte(`{}`), clock.Add(2*time.Minute)); err != nil || !ok {
		t.Fatal(err)
	}
	if _, ok, _ := s.InsertInboxAt(ctx, "dependencytrack", "reconcile", "k", []byte(`{}`), clock); ok {
		t.Error("duplicate key should not insert")
	}
	if items, _ := s.PendingInbox(ctx, 5, 10); len(items) != 0 {
		t.Fatal("item should not be due yet")
	}
	clock = clock.Add(3 * time.Minute)
	if items, _ := s.PendingInbox(ctx, 5, 10); len(items) != 1 {
		t.Fatal("item should be due")
	}
}

func TestTouchSourceProjectKeepsEvidence(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	p := SourceProject{Source: "dependencytrack", ProjectID: "p1", Name: "a", Service: "a", Registered: true, Commit: "abc1234", Ref: "main"}
	_ = s.TouchSourceProject(ctx, p, true)
	p.Commit, p.Ref = "", ""
	_ = s.TouchSourceProject(ctx, p, false)
	var commit, ref string
	if err := s.db.QueryRowContext(ctx, `SELECT last_commit, last_ref FROM source_projects WHERE project_id = 'p1'`).Scan(&commit, &ref); err != nil {
		t.Fatal(err)
	}
	if commit != "abc1234" || ref != "main" {
		t.Errorf("commit=%q ref=%q", commit, ref)
	}
}
