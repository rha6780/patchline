package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/store"
	"go.yaml.in/yaml/v3"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func newStore(t *testing.T) *store.Store {
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
	return store.New(db)
}

// serve returns the API alone, as the server mounts it.
func serve(o Options) http.Handler {
	mux := http.NewServeMux()
	Register(mux, o)
	return mux
}

func TestListFindingsAddsOwners(t *testing.T) {
	st := newStore(t)
	doc := "services:\n  - name: storefront\n    owners: [alice@example.com]\n    slack_channel: '#sf'\n    repositories: [{repo: acme/storefront-api}]\n"
	path := filepath.Join(t.TempDir(), "inv.yaml")
	_ = os.WriteFile(path, []byte(doc), 0o600)
	inv, err := inventory.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_, _, err = st.UpsertFinding(ctx, observation("storefront", true), map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = st.UpsertFinding(ctx, observation("unknown-app", false), map[string]any{})

	h := serve(Options{Findings: st, Inventory: inv, Logger: quiet})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings?service=storefront", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Findings []Finding `json:"findings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Findings) != 1 || len(resp.Findings[0].Owners) != 1 || resp.Findings[0].SlackChannel != "#sf" {
		t.Fatalf("findings = %+v", resp.Findings)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/findings/1/events", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"detected"`) {
		t.Fatalf("events: %d %s", rec.Code, rec.Body)
	}
}

func TestComponentsAndImpactAPI(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	_ = st.TouchSourceProject(ctx, store.SourceProject{Source: "patchline", ProjectID: "app@main", Name: "app", Version: "main", Service: "app"}, true)
	_ = st.ReplaceComponents(ctx, "patchline", "app@main", []store.Component{{PURL: "pkg:npm/lodash@4.17.15", Name: "lodash",
		Version: "4.17.15", Ecosystem: "npm", Package: "lodash"}})
	_ = st.UpsertOSV(ctx, []store.OSVRecord{{ID: "GHSA-p6mc-m468-83gw", Ecosystem: "npm", Modified: "2025-01-01T00:00:00Z",
		Aliases: []string{"CVE-2020-8203"}, Severity: "high",
		Affected: []store.OSVAffected{{Ecosystem: "npm", Package: "lodash", Ranges: []store.OSVRange{{Introduced: "0", Fixed: "4.17.19"}}}}}})
	h := serve(Options{Findings: st, Impact: st, Logger: quiet})
	get := func(path string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return rec.Code, m
	}
	code, m := get("/api/v1/components?q=lodash&version=%3C4.17.19")
	if comps, _ := m["components"].([]any); code != 200 || len(comps) != 1 {
		t.Fatalf("components: %d %v", code, m)
	}
	if code, _ := get("/api/v1/components?q=lodash&version=%3C%3C"); code != http.StatusBadRequest {
		t.Fatalf("bad constraint: %d", code)
	}
	code, m = get("/api/v1/vulnerabilities/CVE-2020-8203")
	if affected, _ := m["affected"].([]any); code != 200 || m["id"] != "CVE-2020-8203" || len(affected) != 1 {
		t.Fatalf("impact: %d %v", code, m)
	}
}

func TestVEX(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	_ = st.TouchSourceProject(ctx, store.SourceProject{Source: "patchline", ProjectID: "app@main", Name: "app", Version: "main", Service: "app"}, true)
	_ = st.ReplaceComponents(ctx, "patchline", "app@main", []store.Component{
		{PURL: "pkg:npm/lodash@4.17.15", Name: "lodash", Version: "4.17.15", Ecosystem: "npm", Package: "lodash"},
		{PURL: "pkg:npm/minimist@1.2.0", Name: "minimist", Version: "1.2.0", Ecosystem: "npm", Package: "minimist"}})
	add := func(purl, name, id string) int64 {
		fid, _, err := st.UpsertFinding(ctx, finding.Observation{Service: "app", Environment: "main", ComponentRef: purl,
			ComponentName: name, ComponentVersion: "x", VulnID: id, Aliases: []string{"GHSA-" + id[4:8] + "-xxxx-xxxx"},
			Severity: "high", Title: "t " + id, Source: "patchline", SourceProject: "app@main"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return fid
	}
	add("pkg:npm/lodash@4.17.15", "lodash", "CVE-2020-8203")
	na := add("pkg:npm/lodash@4.17.15", "lodash", "CVE-2021-23337")
	ra := add("pkg:npm/minimist@1.2.0", "minimist", "CVE-2021-44906")
	decide := func(fid int64, kind, justification string) {
		rid, err := st.CreateRequest(ctx, store.ExceptionRequest{FindingID: fid, Kind: kind, Reason: "because", Justification: justification}, store.Actor{Subject: "a"})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.DecideRequest(ctx, store.Decision{RequestID: rid, Status: store.RequestApproved, By: store.Actor{Subject: "b", Name: "Bob"}}); err != nil {
			t.Fatal(err)
		}
	}
	decide(na, store.RequestNotAffected, "code_not_reachable")
	decide(ra, store.RequestRiskAcceptance, "")

	h := serve(Options{Findings: st, Snapshots: st, Version: "1.2.3", Logger: quiet})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/vex?project=app&version=main&download=1", nil))
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), "app-main.vex.json") {
		t.Fatalf("vex: %d %s", rec.Code, rec.Body)
	}
	var doc struct {
		BOMFormat, SpecVersion string
		Metadata               struct {
			Component struct{ Name, Version string }
		}
		Components      []struct{ PURL string }
		Vulnerabilities []struct {
			ID       string
			Analysis struct {
				State, Justification, Detail string
				Response                     []string
			}
			Affects []struct{ Ref string }
		}
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" || doc.Metadata.Component.Name != "app" ||
		len(doc.Components) != 2 || len(doc.Vulnerabilities) != 3 {
		t.Fatalf("doc = %+v", doc)
	}
	got := map[string]string{}
	for _, v := range doc.Vulnerabilities {
		got[v.ID] = v.Analysis.State + "/" + v.Analysis.Justification + "/" + strings.Join(v.Analysis.Response, ",")
		if len(v.Affects) != 1 || v.Affects[0].Ref == "" {
			t.Errorf("%s affects %+v", v.ID, v.Affects)
		}
	}
	want := map[string]string{"CVE-2020-8203": "in_triage//", "CVE-2021-23337": "not_affected/code_not_reachable/",
		"CVE-2021-44906": "exploitable//will_not_fix"}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s = %q, want %q", id, got[id], w)
		}
	}
	for _, q := range []string{"project=app&version=prod", "version=main"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/vex?"+q, nil))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
}

// TestOpenAPIMatchesRoutes keeps openapi.yaml and Register in step: every
// documented /api path is served, and every served path is documented.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	st := newStore(t)
	h := serve(Options{Findings: st, Impact: st, Snapshots: st, Logger: quiet})
	documented := map[string]bool{}
	for path, ops := range doc.Paths {
		if !strings.HasPrefix(path, "/api/") {
			continue
		}
		for method := range ops {
			documented[strings.ToUpper(method)+" "+path] = true
			concrete := strings.NewReplacer("{id}", "1").Replace(path)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(strings.ToUpper(method), concrete, nil))
			if rec.Code == http.StatusNotFound && strings.Contains(rec.Body.String(), "no such API endpoint") {
				t.Errorf("%s %s is documented but not served", method, path)
			}
		}
	}
	for _, route := range routes(t) {
		if !documented[route] {
			t.Errorf("%s is served but not in openapi.yaml", route)
		}
	}
}

// routes reads the method patterns registered in api.go.
func routes(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(src), "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), `mux.HandleFunc("`); ok {
			pattern, _, _ := strings.Cut(p, `"`)
			if strings.Contains(pattern, " ") {
				out = append(out, pattern)
			}
		}
	}
	if len(out) < 7 {
		t.Fatalf("found %d routes in api.go", len(out))
	}
	return out
}

func TestUnknownAPIPath(t *testing.T) {
	h := serve(Options{Logger: quiet})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/nope", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Header().Get("Content-Type"), "json") {
		t.Fatalf("unknown path: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.yaml", nil))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "openapi: 3.1") {
		t.Fatalf("openapi: %d", rec.Code)
	}
}
