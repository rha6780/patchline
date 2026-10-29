package job

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/policy"
	"github.com/rha6780/patchline/internal/store"
)

func setup(t *testing.T) (*store.Store, *inventory.Inventory) {
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
	path := filepath.Join(t.TempDir(), "inv.yaml")
	_ = os.WriteFile(path, []byte("services:\n  - name: web\n    exposure: internet\n    repositories: [{repo: acme/web}]\n  - name: batch\n    repositories: [{repo: acme/batch}]\n"), 0o600)
	inv, err := inventory.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return store.New(db), inv
}

func events(t *testing.T, st *store.Store, id int64) []string {
	t.Helper()
	evs, err := st.FindingEvents(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Kind)
	}
	return kinds
}

func TestSLAJob(t *testing.T) {
	ctx := context.Background()
	st, inv := setup(t)

	var catalog atomic.Value
	catalog.Store(`{"catalogVersion":"1","vulnerabilities":[{"cveID":"CVE-2017-5638"}]}`)
	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(catalog.Load().(string)))
	}))
	defer kevSrv.Close()

	webID, _, _ := st.UpsertFinding(ctx, finding.Observation{Service: "web", Registered: true, Environment: "main",
		ComponentRef: "a", VulnID: "CVE-2021-44228", Severity: finding.SeverityMedium}, nil)
	batchID, _, _ := st.UpsertFinding(ctx, finding.Observation{Service: "batch", Registered: true, Environment: "main",
		ComponentRef: "b", VulnID: "CVE-2024-1", Severity: finding.SeverityHigh}, nil)
	f0, _ := st.GetFinding(ctx, webID)
	start, _ := time.Parse(store.TimeLayout, *f0.SLAStartedAt)

	clock := start
	changes := 0
	j := &SLA{Store: st, Policy: policy.Default(), Inventory: inv, KEVURL: kevSrv.URL, KEVRefresh: time.Hour,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return clock },
		OnChange: func() { changes++ }}

	// First evaluation: silent, due dates set. web is internet-exposed: medium -> high (30d).
	if err := j.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	web, _ := st.GetFinding(ctx, webID)
	if web.EffectiveSeverity != "high" || web.DueAt == nil || *web.DueAt != store.FormatTime(start.AddDate(0, 0, 30)) {
		t.Fatalf("web after first run: %+v", web)
	}
	if got := events(t, st, webID); len(got) != 1 {
		t.Fatalf("first evaluation must be silent, events = %v", got)
	}
	batch, _ := st.GetFinding(ctx, batchID)
	batchStart, _ := time.Parse(store.TimeLayout, *batch.SLAStartedAt)
	if batch.EffectiveSeverity != "high" || *batch.DueAt != store.FormatTime(batchStart.AddDate(0, 0, 30)) {
		t.Fatalf("batch: %+v", batch)
	}

	// CVE-2021-44228 enters KEV: escalated to critical (7d), event recorded.
	catalog.Store(`{"catalogVersion":"2","vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`)
	clock = clock.Add(2 * time.Hour)
	changes = 0
	if err := j.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	web, _ = st.GetFinding(ctx, webID)
	if !web.KEV || web.EffectiveSeverity != "critical" || *web.DueAt != store.FormatTime(start.AddDate(0, 0, 7)) || changes != 1 {
		t.Fatalf("after KEV: %+v changes=%d", web, changes)
	}
	if got := events(t, st, webID); got[len(got)-1] != finding.EventSLAChanged {
		t.Fatalf("events = %v", got)
	}

	// Nothing changes: no events.
	changes = 0
	_ = j.RunOnce(ctx)
	if changes != 0 {
		t.Fatal("idle run should not record anything")
	}

	// 5 days in: due within 3 days -> due_soon once.
	clock = start.AddDate(0, 0, 5)
	_ = j.RunOnce(ctx)
	_ = j.RunOnce(ctx)
	// Past due -> overdue; again after 7 days.
	clock = start.AddDate(0, 0, 8)
	_ = j.RunOnce(ctx)
	_ = j.RunOnce(ctx)
	clock = start.AddDate(0, 0, 15)
	_ = j.RunOnce(ctx)

	evs, _ := st.FindingEvents(ctx, webID)
	var reminders []string
	for _, e := range evs {
		if e.Kind == finding.EventReminder {
			reminders = append(reminders, string(e.Evidence))
		}
	}
	if len(reminders) != 3 {
		t.Fatalf("reminders = %v, want due_soon + overdue x2", reminders)
	}
	for i, want := range []string{"due_soon", "overdue", "overdue"} {
		if !strings.Contains(reminders[i], `"kind":"`+want+`"`) {
			t.Errorf("reminder %d = %s, want %s", i, reminders[i], want)
		}
	}
}

func TestKEVRefreshFailureKeepsWorking(t *testing.T) {
	ctx := context.Background()
	st, inv := setup(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer srv.Close()
	id, _, _ := st.UpsertFinding(ctx, finding.Observation{Service: "batch", Registered: true, Environment: "main",
		ComponentRef: "b", VulnID: "CVE-2024-1", Severity: finding.SeverityLow}, nil)
	j := &SLA{Store: st, Policy: policy.Default(), Inventory: inv, KEVURL: srv.URL,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := j.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFinding(ctx, id); f.EffectiveSeverity != "low" || f.DueAt == nil {
		t.Fatalf("finding = %+v", f)
	}
}
