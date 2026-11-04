package dependencytrack

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/source"
	"github.com/rha6780/patchline/internal/store"
)

var testEnv = source.Env{
	Resolve: func(p string) (string, string, bool) {
		if p == "storefront-api" {
			return "storefront", "acme/storefront-api", true
		}
		return p, "", false
	},
	Now: func() time.Time { return time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC) },
}

type fetcher struct{ sightings []Sighting }

func (f fetcher) ProjectSightings(_ context.Context, p Project) ([]Sighting, error) {
	out := make([]Sighting, len(f.sightings))
	for i, s := range f.sightings {
		s.Project = p
		out[i] = s
	}
	return out, nil
}

func TestAccept(t *testing.T) {
	a := &Adapter{}
	body := fixture(t, "new_vulnerability.json")
	req := httptest.NewRequest("POST", "/webhooks/dependency-track?token=wrong", nil)
	if _, _, err := a.Accept(req, body, source.Secrets{WebhookToken: "s3cret"}); !errors.Is(err, source.ErrUnauthorized) {
		t.Fatalf("wrong token: %v", err)
	}
	req = httptest.NewRequest("POST", "/webhooks/dependency-track", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	if _, _, err := a.Accept(req, []byte(`{"nope":1}`), source.Secrets{WebhookToken: "s3cret"}); err == nil || errors.Is(err, source.ErrUnauthorized) {
		t.Fatalf("bad body: %v", err)
	}
	event, key, err := a.Accept(req, body, source.Secrets{WebhookToken: "s3cret"})
	if err != nil || event != GroupNewVulnerability || len(key) != 64 {
		t.Fatalf("accept: %q %q %v", event, key, err)
	}
}

func TestHandleNotifications(t *testing.T) {
	ctx := context.Background()
	a := &Adapter{}
	item := func(name string) store.InboxItem {
		return store.InboxItem{ID: 7, Source: Name, Payload: fixture(t, name)}
	}

	out, err := a.Handle(ctx, item("new_vulnerability.json"), testEnv)
	if err != nil || len(out.Sightings) != 2 || len(out.Projects) != 2 || out.Snapshot != nil {
		t.Fatalf("new vulnerability: %+v %v", out, err)
	}
	o := out.Sightings[0].Observation
	if o.Ref.Source != Name || o.Ref.Project == "" || o.Ref.Component == "" || o.Ref.Vuln == "" || o.Environment == "" {
		t.Fatalf("observation = %+v", o)
	}

	out, err = a.Handle(ctx, item("project_audit_change.json"), testEnv)
	if err != nil || len(out.StateChanges) != 1 || out.StateChanges[0].Ref.Source != Name {
		t.Fatalf("audit change: %+v %v", out, err)
	}

	// BOM_PROCESSED: the project is touched with its BOM; without the API
	// nothing is scheduled.
	out, err = a.Handle(ctx, item("bom_processed.json"), testEnv)
	if err != nil || len(out.Projects) != 1 || !out.Projects[0].BOM || len(out.Later) != 0 || !strings.HasPrefix(out.Note, "skipped") {
		t.Fatalf("bom without api: %+v %v", out, err)
	}
	a.Client = fetcher{}
	a.ReconcileDelay = time.Minute
	out, err = a.Handle(ctx, item("bom_processed.json"), testEnv)
	if err != nil || len(out.Later) != 1 || out.Later[0].EventType != EventReconcile || !out.Later[0].At.Equal(testEnv.Now().Add(time.Minute)) {
		t.Fatalf("bom with api: %+v %v", out, err)
	}
}

func TestReconcileIsASnapshot(t *testing.T) {
	ctx := context.Background()
	s := Sighting{Component: Component{UUID: "c1", Name: "express", Version: "4.17.1", PURL: "pkg:npm/express@4.17.1"},
		Vulnerability: Vulnerability{UUID: "v1", VulnID: "GHSA-rv95-896h-c2vc", Aliases: Aliases{"CVE-2024-29041"}, Severity: "MEDIUM", Source: "GITHUB"}}
	a := &Adapter{Client: fetcher{sightings: []Sighting{s}}}
	payload := `{"project":{"uuid":"p1","name":"storefront-api","version":"prod"},"bom":{"commit":"abc"},"bom_processed_inbox_id":3}`
	out, err := a.Handle(ctx, store.InboxItem{Source: Name, EventType: EventReconcile, Payload: []byte(payload)}, testEnv)
	if err != nil {
		t.Fatal(err)
	}
	if out.Snapshot == nil || out.Snapshot.Project != "p1" || len(out.Sightings) != 1 {
		t.Fatalf("outcome = %+v", out)
	}
	o := out.Sightings[0].Observation
	want := finding.Ref{Source: Name, Project: "p1", Component: "c1", Vuln: "v1", VulnSource: "GITHUB", VulnName: "GHSA-rv95-896h-c2vc"}
	if o.Service != "storefront" || !o.Registered || o.Environment != "prod" || o.VulnID != "CVE-2024-29041" || o.Ref != want {
		t.Fatalf("observation = %+v", o)
	}
	if out.Sightings[0].Evidence["commit"] != "abc" {
		t.Fatalf("evidence = %v", out.Sightings[0].Evidence)
	}
}
