package intake

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/sbom"
	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/source/osv"
	"github.com/rha6780/patchline/internal/store"
)

// fakeMatcher reports vulns by purl.
type fakeMatcher struct {
	vulns map[string][]osv.Match
	ready bool
}

func (f *fakeMatcher) Ready(context.Context) (bool, error) { return f.ready, nil }
func (f *fakeMatcher) Match(_ context.Context, c store.Component) ([]osv.Match, error) {
	return f.vulns[c.PURL], nil
}

const (
	log4j  = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	lodash = "pkg:npm/lodash@4.17.15"
)

func bomWith(purls ...string) json.RawMessage {
	var cs []map[string]string
	for _, p := range purls {
		cs = append(cs, map[string]string{"name": p, "purl": p})
	}
	b, _ := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "components": cs,
		"metadata": map[string]any{"properties": []map[string]string{{"name": sbom.PropertyCommit, "value": "abc1234"}}}})
	return b
}

func upload(t *testing.T, st *store.Store, key string, bom json.RawMessage) {
	t.Helper()
	payload, _ := json.Marshal(sbom.Upload{Project: "storefront-api", Version: "main", BOM: bom})
	if _, _, err := st.InsertInbox(context.Background(), SourcePatchline, EventSBOM, key, payload); err != nil {
		t.Fatal(err)
	}
}

func findingFor(t *testing.T, st *store.Store, ref string) store.Finding {
	t.Helper()
	list, err := st.ListFindings(context.Background(), store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range list {
		if f.ComponentRef == ref {
			return f
		}
	}
	t.Fatalf("no finding for %s in %+v", ref, list)
	return store.Finding{}
}

func TestSBOMUploadDetectsAndResolves(t *testing.T) {
	ctx := context.Background()
	p, st := setup(t, nil)
	m := &fakeMatcher{ready: true, vulns: map[string][]osv.Match{
		log4j:  {{ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}, Severity: "critical", Summary: "Log4Shell", Range: ">= 2.13.0, < 2.15.0", Fixed: "2.15.0"}},
		lodash: {{ID: "GHSA-p6mc-m468-83gw", Aliases: []string{"CVE-2020-8203"}, Severity: "high"}},
	}}
	p.Matcher = m

	upload(t, st, "u1", bomWith(log4j, lodash))
	drain(t, p)
	f := findingFor(t, st, log4j)
	if f.VulnID != "CVE-2021-44228" || f.Service != "storefront" || f.Environment != "main" || f.Severity != "critical" ||
		f.State != "new" || f.Title != "Log4Shell" {
		t.Fatalf("log4j finding = %+v", f)
	}
	events, _ := st.FindingEvents(ctx, f.ID)
	var ev map[string]any
	_ = json.Unmarshal(events[0].Evidence, &ev)
	if ev["source"] != SourcePatchline || ev["fixed_version"] != "2.15.0" || ev["commit"] != "abc1234" {
		t.Errorf("detected evidence = %s", events[0].Evidence)
	}
	comps, _ := st.Components(ctx, SourcePatchline, "storefront-api@main")
	if len(comps) != 2 {
		t.Errorf("snapshot = %+v", comps)
	}

	// log4j upgraded: its finding resolves, lodash stays.
	upload(t, st, "u2", bomWith("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", lodash))
	drain(t, p)
	if f := findingFor(t, st, log4j); f.State != "resolved" {
		t.Fatalf("after upgrade: %s", f.State)
	}
	if f := findingFor(t, st, lodash); f.State != "new" {
		t.Fatalf("lodash after upgrade: %s", f.State)
	}

	// A new advisory for the current snapshot: re-analysis finds it without
	// a new upload.
	m.vulns["pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"] = []osv.Match{{ID: "GHSA-new", Aliases: []string{"CVE-2099-1"}, Severity: "medium"}}
	if _, _, err := st.InsertInbox(ctx, SourcePatchline, EventReanalyze, "r1", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	drain(t, p)
	if f := findingFor(t, st, "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"); f.VulnID != "CVE-2099-1" || f.State != "new" {
		t.Fatalf("after re-analysis: %+v", f)
	}
}

func TestSBOMNotReadyDoesNotResolve(t *testing.T) {
	p, st := setup(t, nil)
	m := &fakeMatcher{ready: true, vulns: map[string][]osv.Match{lodash: {{ID: "GHSA-x", Severity: "high"}}}}
	p.Matcher = m
	upload(t, st, "u1", bomWith(lodash))
	drain(t, p)
	// The data is being re-loaded (no matches yet): nothing may resolve.
	m.ready, m.vulns = false, nil
	upload(t, st, "u2", bomWith(lodash))
	drain(t, p)
	if f := findingFor(t, st, lodash); f.State != "new" {
		t.Fatalf("resolved while the data was not ready: %s", f.State)
	}
}

func TestDTAndPatchlineShareOneFinding(t *testing.T) {
	ctx := context.Background()
	dtLog4j := dependencytrack.Sighting{
		Component:     dependencytrack.Component{UUID: "c1", Group: "org.apache.logging.log4j", Name: "log4j-core", Version: "2.14.1", PURL: log4j},
		Vulnerability: dependencytrack.Vulnerability{UUID: "v1", VulnID: "CVE-2021-44228", Source: "NVD", Severity: "CRITICAL", Title: "from DT"},
	}
	dt := &fakeDT{sightings: []dependencytrack.Sighting{dtLog4j}}
	p, st := setup(t, dt)
	p.ReconcileDelay = time.Nanosecond
	p.Matcher = &fakeMatcher{ready: true, vulns: map[string][]osv.Match{
		log4j: {{ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}, Severity: "high", Summary: "from OSV"}},
	}}

	// Patchline sees it first, then Dependency-Track: one finding, DT's
	// severity and title, both sources listed.
	upload(t, st, "u1", bomWith(log4j))
	drain(t, p)
	enqueueBOM(t, st, "bom-1")
	drain(t, p)
	list, _ := st.ListFindings(ctx, store.FindingFilter{})
	if len(list) != 1 {
		t.Fatalf("findings = %d, want one shared finding", len(list))
	}
	f := list[0]
	if f.Severity != "critical" || f.Title != "from DT" || f.DTVulnerabilityUUID != "v1" {
		t.Fatalf("shared finding = %+v", f)
	}
	sightings, _ := st.FindingSightings(ctx, f.ID)
	if len(sightings) != 2 || sightings[0].Source != finding.SourceDependencyTrack || sightings[1].Source != finding.SourcePatchline {
		t.Fatalf("sightings = %+v", sightings)
	}

	// Patchline re-reports with its own severity: DT's stays.
	upload(t, st, "u2", bomWith(log4j))
	drain(t, p)
	if f := findingFor(t, st, log4j); f.Severity != "critical" || f.Title != "from DT" {
		t.Fatalf("severity flipped: %+v", f)
	}

	// Fixed in the SBOM uploaded to Patchline, but Dependency-Track still
	// reports it: still open.
	upload(t, st, "u3", bomWith("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"))
	drain(t, p)
	if f := findingFor(t, st, log4j); f.State != "new" {
		t.Fatalf("resolved while DT still reports it: %s", f.State)
	}
	// Dependency-Track's next BOM agrees: resolved.
	dt.sightings = nil
	enqueueBOM(t, st, "bom-2")
	drain(t, p)
	if f := findingFor(t, st, log4j); f.State != "resolved" {
		t.Fatalf("after both sources stopped: %s", f.State)
	}
}

func TestSBOMWithoutMatcherIsStored(t *testing.T) {
	ctx := context.Background()
	p, st := setup(t, nil)
	upload(t, st, "u1", bomWith(lodash))
	drain(t, p)
	if comps, _ := st.Components(ctx, SourcePatchline, "storefront-api@main"); len(comps) != 1 {
		t.Fatalf("snapshot = %+v", comps)
	}
	projects, _ := st.SourceProjects(ctx, SourcePatchline)
	if len(projects) != 1 || projects[0].Service != "storefront" || projects[0].Commit != "abc1234" {
		t.Fatalf("projects = %+v", projects)
	}
	if list, _ := st.ListFindings(ctx, store.FindingFilter{}); len(list) != 0 {
		t.Fatalf("findings without a matcher: %+v", list)
	}
}
