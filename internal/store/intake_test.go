package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
)

func TestInboxLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }

	id, inserted, err := s.InsertInbox(ctx, "dependencytrack", "NEW_VULNERABILITY", "k1", []byte(`{}`))
	if err != nil || !inserted {
		t.Fatalf("insert: id=%d inserted=%v err=%v", id, inserted, err)
	}
	dup, inserted, err := s.InsertInbox(ctx, "dependencytrack", "NEW_VULNERABILITY", "k1", []byte(`{}`))
	if err != nil || inserted || dup != id {
		t.Fatalf("duplicate: id=%d inserted=%v err=%v, want id %d not inserted", dup, inserted, err, id)
	}

	items, err := s.PendingInbox(ctx, 5, 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("pending: %d items, err %v", len(items), err)
	}

	if err := s.MarkInboxFailed(ctx, id, errors.New("boom"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if items, _ := s.PendingInbox(ctx, 5, 10); len(items) != 0 {
		t.Fatal("failed item should wait for its retry time")
	}
	clock = clock.Add(2 * time.Minute)
	items, _ = s.PendingInbox(ctx, 5, 10)
	if len(items) != 1 || items[0].Attempts != 1 {
		t.Fatalf("after backoff: %+v", items)
	}
	if items, _ := s.PendingInbox(ctx, 1, 10); len(items) != 0 {
		t.Fatal("item at max attempts should not be returned")
	}

	if err := s.MarkInboxDone(ctx, id, ""); err != nil {
		t.Fatal(err)
	}
	if items, _ := s.PendingInbox(ctx, 5, 10); len(items) != 0 {
		t.Fatal("done item should not be pending")
	}
}

func TestUpsertFinding(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	obs := finding.Observation{
		Service: "storefront", Registered: true, Repository: "acme/storefront-api", Environment: "main",
		ComponentRef: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", ComponentName: "log4j-core", ComponentVersion: "2.14.1",
		VulnID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, Severity: finding.SeverityCritical,
		DTProjectUUID: "p1",
	}
	id, created, err := s.UpsertFinding(ctx, obs, map[string]any{"inbox_id": 1})
	if err != nil || !created {
		t.Fatalf("first upsert: id=%d created=%v err=%v", id, created, err)
	}

	obs.Severity = finding.SeverityHigh
	id2, created, err := s.UpsertFinding(ctx, obs, map[string]any{"inbox_id": 2})
	if err != nil || created || id2 != id {
		t.Fatalf("second upsert: id=%d created=%v err=%v", id2, created, err)
	}

	// Same vulnerability in prod is a separate finding.
	obs.Environment = "prod"
	if _, created, _ := s.UpsertFinding(ctx, obs, nil); !created {
		t.Fatal("prod should be a new finding")
	}

	list, err := s.ListFindings(ctx, FindingFilter{Service: "storefront", Environment: "main"})
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %d err %v", len(list), err)
	}
	f := list[0]
	if f.State != string(finding.StateNew) || f.Severity != finding.SeverityHigh || len(f.Aliases) != 1 || !f.Registered {
		t.Errorf("finding = %+v", f)
	}

	events, err := s.FindingEvents(ctx, id)
	if err != nil || len(events) != 1 || events[0].Kind != finding.EventDetected || string(events[0].Evidence) != `{"inbox_id":1}` {
		t.Fatalf("events = %+v err %v (want one detected event from the first sighting)", events, err)
	}
}

func TestTouchSourceProject(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	p := SourceProject{Source: "dependencytrack", ProjectID: "p1", Name: "storefront-api", Version: "main", Service: "storefront", Registered: true}
	if err := s.TouchSourceProject(ctx, p, true); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchSourceProject(ctx, p, false); err != nil {
		t.Fatal(err)
	}
	var bom *string
	if err := s.db.QueryRowContext(ctx, `SELECT last_bom_at FROM source_projects WHERE project_id = 'p1'`).Scan(&bom); err != nil || bom == nil {
		t.Fatalf("last_bom_at should survive a non-BOM touch: %v %v", bom, err)
	}
}
