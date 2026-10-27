package intake

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/store"
)

const testInventory = `
services:
  - name: storefront
    owners: [alice@example.com]
    repositories:
      - repo: acme/storefront-api
`

type fakeDT struct {
	sightings []dependencytrack.Sighting
	err       error
	calls     int
}

func (f *fakeDT) ProjectSightings(_ context.Context, p dependencytrack.Project) ([]dependencytrack.Sighting, error) {
	f.calls++
	out := make([]dependencytrack.Sighting, len(f.sightings))
	for i, s := range f.sightings {
		s.Project = p
		out[i] = s
	}
	return out, f.err
}

func setup(t *testing.T, dt FindingsFetcher) (*Processor, *store.Store) {
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

	path := filepath.Join(t.TempDir(), "inv.yaml")
	if err := os.WriteFile(path, []byte(testInventory), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p := &Processor{Store: st, Inventory: inv, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if dt != nil {
		p.DT = dt
	}
	return p, st
}

func enqueue(t *testing.T, st *store.Store, fixture string) int64 {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "source", "dependencytrack", "testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := st.InsertInbox(context.Background(), SourceDependencyTrack, "x", fixture, body)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestNewVulnerabilityCreatesFindings(t *testing.T) {
	ctx := context.Background()
	p, st := setup(t, nil)
	enqueue(t, st, "new_vulnerability.json")

	n, err := p.ProcessPending(ctx)
	if err != nil || n != 1 {
		t.Fatalf("processed %d, err %v", n, err)
	}

	list, err := st.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("findings = %d, want 2 (two affected projects)", len(list))
	}
	byService := map[string]store.Finding{}
	for _, f := range list {
		byService[f.Service] = f
	}

	reg := byService["storefront"]
	if !reg.Registered || reg.Repository != "acme/storefront-api" || reg.Environment != "main" {
		t.Errorf("registered finding = %+v", reg)
	}
	if reg.VulnID != "CVE-2021-44228" || len(reg.Aliases) != 1 || reg.Aliases[0] != "GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("canonical id: got %s %v, want CVE with GHSA alias", reg.VulnID, reg.Aliases)
	}
	if reg.Severity != "critical" || reg.State != "new" {
		t.Errorf("severity/state = %s/%s", reg.Severity, reg.State)
	}

	unreg, ok := byService["unknown-app"]
	if !ok || unreg.Registered || unreg.Environment != DefaultEnvironment {
		t.Errorf("unregistered finding = %+v (ok=%v)", unreg, ok)
	}

	// Reprocessing the same event (a different inbox row) does not duplicate.
	body, _ := os.ReadFile(filepath.Join("..", "source", "dependencytrack", "testdata", "new_vulnerability.json"))
	_, _, _ = st.InsertInbox(ctx, SourceDependencyTrack, "x", "other-key", body)
	if _, err := p.ProcessPending(ctx); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListFindings(ctx, store.FindingFilter{}); len(list) != 2 {
		t.Fatalf("after replay: %d findings, want 2", len(list))
	}
}

func TestNewVulnerableDependency(t *testing.T) {
	ctx := context.Background()
	p, st := setup(t, nil)
	enqueue(t, st, "new_vulnerable_dependency.json")
	if _, err := p.ProcessPending(ctx); err != nil {
		t.Fatal(err)
	}
	list, _ := st.ListFindings(ctx, store.FindingFilter{Service: "storefront"})
	if len(list) != 2 {
		t.Fatalf("findings = %d, want 2", len(list))
	}
}

func TestBOMProcessedFetchesFindings(t *testing.T) {
	ctx := context.Background()
	dt := &fakeDT{sightings: []dependencytrack.Sighting{{
		Component:     dependencytrack.Component{UUID: "c1", Name: "express", Version: "4.17.1", PURL: "pkg:npm/express@4.17.1"},
		Vulnerability: dependencytrack.Vulnerability{UUID: "v1", VulnID: "CVE-2024-29041", Severity: "MEDIUM"},
	}}}
	p, st := setup(t, dt)
	enqueue(t, st, "bom_processed.json")

	if _, err := p.ProcessPending(ctx); err != nil {
		t.Fatal(err)
	}
	if dt.calls != 1 {
		t.Fatalf("DT calls = %d, want 1", dt.calls)
	}
	list, _ := st.ListFindings(ctx, store.FindingFilter{})
	if len(list) != 1 || list[0].Service != "storefront" || list[0].ComponentRef != "pkg:npm/express@4.17.1" {
		t.Fatalf("findings = %+v", list)
	}
}

func TestBOMProcessedWithoutDTIsSkipped(t *testing.T) {
	ctx := context.Background()
	p, st := setup(t, nil)
	enqueue(t, st, "bom_processed.json")
	if _, err := p.ProcessPending(ctx); err != nil {
		t.Fatal(err)
	}
	if pending, _ := st.PendingInbox(ctx, 5, 10); len(pending) != 0 {
		t.Fatal("skipped item should be marked done, not retried")
	}
}

func TestFailureIsRetriedLater(t *testing.T) {
	ctx := context.Background()
	dt := &fakeDT{err: errors.New("dependency-track down")}
	p, st := setup(t, dt)
	enqueue(t, st, "bom_processed.json")

	if _, err := p.ProcessPending(ctx); err != nil {
		t.Fatal(err)
	}
	// Backoff keeps it out of the next immediate pass.
	if n, _ := p.ProcessPending(ctx); n != 0 {
		t.Fatalf("processed %d right after failure, want 0", n)
	}
}

func TestBackoff(t *testing.T) {
	want := []string{"30s", "1m0s", "2m0s", "4m0s", "8m0s", "16m0s", "30m0s", "30m0s"}
	for i, w := range want {
		if got := backoff(i + 1).String(); got != w {
			t.Errorf("backoff(%d) = %s, want %s", i+1, got, w)
		}
	}
}
