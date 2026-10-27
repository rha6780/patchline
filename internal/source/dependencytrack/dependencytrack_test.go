package dependencytrack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNewVulnerabilitySightings(t *testing.T) {
	n, err := ParseNotification(fixture(t, "new_vulnerability.json"))
	if err != nil {
		t.Fatal(err)
	}
	if n.Group != GroupNewVulnerability {
		t.Fatalf("group = %q", n.Group)
	}
	got, err := n.Sightings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("sightings = %d, want 2 (one per affected project)", len(got))
	}
	s := got[0]
	if s.Project.Name != "storefront-api" || s.Project.Version != "main" {
		t.Errorf("project = %+v", s.Project)
	}
	if s.Component.Ref() != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("ref = %q", s.Component.Ref())
	}
	if s.Vulnerability.VulnID != "GHSA-jfh8-c2jp-5v3q" || !reflect.DeepEqual([]string(s.Vulnerability.Aliases), []string{"CVE-2021-44228"}) {
		t.Errorf("vulnerability = %+v", s.Vulnerability)
	}
}

func TestNewVulnerableDependencySightings(t *testing.T) {
	n, err := ParseNotification(fixture(t, "new_vulnerable_dependency.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := n.Sightings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("sightings = %d, want 2 (one per vulnerability)", len(got))
	}
	if got[1].Vulnerability.VulnID != "CVE-2014-3596" || got[1].Project.UUID == "" {
		t.Errorf("second sighting = %+v", got[1])
	}
}

func TestBOMProcessedProject(t *testing.T) {
	n, err := ParseNotification(fixture(t, "bom_processed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := n.Sightings(); s != nil {
		t.Errorf("BOM_PROCESSED should carry no sightings, got %d", len(s))
	}
	p, err := n.SubjectProject()
	if err != nil {
		t.Fatal(err)
	}
	if p.UUID != "6fb1820f-5280-4577-ac51-40124aabe307" || p.Name != "storefront-api" {
		t.Errorf("project = %+v", p)
	}
}

func TestParseNotificationInvalid(t *testing.T) {
	for _, body := range []string{`not json`, `{}`, `{"notification":{}}`} {
		if _, err := ParseNotification([]byte(body)); err == nil {
			t.Errorf("%q: expected error", body)
		}
	}
}

func TestComponentRef(t *testing.T) {
	tests := []struct {
		c    Component
		want string
	}{
		{Component{PURL: "pkg:npm/express@4.19.2", CPE: "cpe:x"}, "pkg:npm/express@4.19.2"},
		{Component{CPE: "cpe:2.3:a:f5:nginx:1.27.4:*:*:*:*:*:*:*"}, "cpe:2.3:a:f5:nginx:1.27.4:*:*:*:*:*:*:*"},
		{Component{Group: "acme", Name: "lib", Version: "1.0"}, "dependency-track:acme/lib@1.0"},
	}
	for _, tc := range tests {
		if got := tc.c.Ref(); got != tc.want {
			t.Errorf("Ref() = %q, want %q", got, tc.want)
		}
	}
}

func TestClientProjectSightings(t *testing.T) {
	var gotKey, gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotPath, gotQuery = r.Header.Get("X-Api-Key"), r.URL.Path, r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture(t, "project_findings.json"))
	}))
	defer srv.Close()

	p := Project{UUID: "6fb1820f-5280-4577-ac51-40124aabe307", Name: "storefront-api", Version: "main"}
	got, err := NewClient(srv.URL+"/", "secret", nil).ProjectSightings(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if gotKey != "secret" || gotPath != "/api/v1/finding/project/"+p.UUID || gotQuery != "suppressed=false" {
		t.Errorf("request: key=%q path=%q query=%q", gotKey, gotPath, gotQuery)
	}
	if len(got) != 1 {
		t.Fatalf("sightings = %d, want 1 (suppressed one dropped)", len(got))
	}
	s := got[0]
	if s.Project != p {
		t.Errorf("project = %+v", s.Project)
	}
	if want := []string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"}; !reflect.DeepEqual([]string(s.Vulnerability.Aliases), want) {
		t.Errorf("aliases = %v, want %v", s.Vulnerability.Aliases, want)
	}
}

func TestClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL, "bad", nil).ProjectSightings(context.Background(), Project{UUID: "x"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestAuditChange(t *testing.T) {
	n, err := ParseNotification(fixture(t, "project_audit_change.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := n.AuditChange()
	if err != nil {
		t.Fatal(err)
	}
	if a.Analysis.State != "IN_TRIAGE" || a.Analysis.Project != "6fb1820f-5280-4577-ac51-40124aabe307" {
		t.Fatalf("analysis = %+v", a.Analysis)
	}
	if st, ok := a.Analysis.FindingState(); !ok || st != "in_progress" {
		t.Fatalf("state = %q %v", st, ok)
	}
}

func TestAnalysisFindingState(t *testing.T) {
	tests := []struct {
		a    Analysis
		want string
	}{
		{Analysis{State: "NOT_SET"}, "new"},
		{Analysis{State: "IN_TRIAGE"}, "in_progress"},
		{Analysis{State: "EXPLOITABLE"}, "in_progress"},
		{Analysis{State: "RESOLVED"}, "awaiting_verification"},
		{Analysis{State: "NOT_AFFECTED"}, "not_affected"},
		{Analysis{State: "FALSE_POSITIVE", Suppressed: true}, "not_affected"},
		{Analysis{State: "EXPLOITABLE", Suppressed: true}, "risk_accepted"},
	}
	for _, tc := range tests {
		if got, ok := tc.a.FindingState(); !ok || string(got) != tc.want {
			t.Errorf("%+v -> %q (%v), want %q", tc.a, got, ok, tc.want)
		}
	}
	if _, ok := (Analysis{State: "SOMETHING_NEW"}).FindingState(); ok {
		t.Error("unknown state should not map")
	}
}

func TestClientVulnerability(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"vulnId":"GHSA-jfh8-c2jp-5v3q","source":"GITHUB","patchedVersions":"2.15.0",
		  "affectedComponents":[{"identityType":"PURL","identity":"pkg:maven/org.apache.logging.log4j/log4j-core",
		  "versionType":"RANGE","versionStartIncluding":"2.0-beta9","versionEndExcluding":"2.15.0"}]}`))
	}))
	defer srv.Close()
	v, err := NewClient(srv.URL, "k", nil).Vulnerability(context.Background(), "GITHUB", "GHSA-jfh8-c2jp-5v3q")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/vulnerability/source/GITHUB/vuln/GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("path = %s", gotPath)
	}
	if len(v.AffectedComponents) != 1 || v.AffectedComponents[0].VersionEndExcluding != "2.15.0" || v.PatchedVersions != "2.15.0" {
		t.Errorf("v = %+v", v)
	}
}
