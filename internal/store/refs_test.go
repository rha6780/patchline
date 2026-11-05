package store

import (
	"context"
	"io/fs"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/rha6780/patchline/internal/finding"
)

// TestFindingRefsBackfill migrates a database at version 13 with a
// Dependency-Track finding (open), a resolved one, a merged one and a
// Patchline-only one, and checks the refs the migration creates.
func TestFindingRefsBackfill(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fsys, _ := fs.Sub(embedded, "migrations")
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, fsys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 13); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO findings (id, service, environment, component_purl, vuln_id, severity, state,
			dt_project_uuid, dt_component_uuid, dt_vulnerability_uuid, dt_vuln_source, dt_vuln_id)
		 VALUES (1, 'a', 'main', 'pkg:npm/x@1', 'CVE-1', 'high', 'new', 'p1', 'c1', 'v1', 'NVD', 'CVE-1')`,
		`INSERT INTO findings (id, service, environment, component_purl, vuln_id, severity, state,
			dt_project_uuid, dt_component_uuid, dt_vulnerability_uuid)
		 VALUES (2, 'a', 'main', 'pkg:npm/y@1', 'CVE-2', 'high', 'resolved', 'p1', 'c2', 'v2')`,
		`INSERT INTO findings (id, service, environment, component_purl, vuln_id, severity, state,
			dt_project_uuid, dt_component_uuid, dt_vulnerability_uuid, primary_source)
		 VALUES (3, 'a', 'main', 'pkg:npm/z@1', 'CVE-3', 'high', 'new', 'p1', 'c3', 'v3', 'dependencytrack')`,
		`INSERT INTO findings (id, service, environment, component_purl, vuln_id, severity, state, primary_source)
		 VALUES (4, 'a', 'prod', 'pkg:npm/w@1', 'GHSA-4', 'low', 'new', 'patchline')`,
		`INSERT INTO finding_sightings (finding_id, source, project_id, first_seen_at, last_seen_at) VALUES
			(1, 'dependencytrack', 'p1', 't', 't'), (3, 'dependencytrack', 'p1', 't', 't'),
			(3, 'patchline', 'a@main', 't', 't'), (4, 'patchline', 'a@prod', 't', 't')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}

	st := New(db)
	want := map[int64][]finding.Ref{
		1: {{Source: "dependencytrack", Project: "p1", Component: "c1", Vuln: "v1", VulnSource: "NVD", VulnName: "CVE-1"}},
		2: {{Source: "dependencytrack", Project: "p1", Component: "c2", Vuln: "v2"}}, // resolved: kept
		3: {{Source: "dependencytrack", Project: "p1", Component: "c3", Vuln: "v3"},
			{Source: "patchline", Project: "a@main", Component: "pkg:npm/z@1", Vuln: "CVE-3"}},
		4: {{Source: "patchline", Project: "a@prod", Component: "pkg:npm/w@1", Vuln: "GHSA-4"}},
	}
	for id, w := range want {
		got, err := st.FindingRefs(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("finding %d refs = %+v\nwant %+v", id, got, w)
		}
	}
}

// TestTwoDependencyTrackProjects: two Dependency-Track projects (an app
// and its image, say) report the same finding. Each keeps its ref, so an
// analysis change in either one reaches the finding. Before refs, the
// second upsert overwrote the first project's ids and the change was lost.
func TestTwoDependencyTrackProjects(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	obs := func(project, component string) finding.Observation {
		return finding.Observation{Service: "storefront", Registered: true, Environment: "prod",
			ComponentRef: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", VulnID: "CVE-2021-44228",
			Severity: finding.SeverityCritical, DTProjectUUID: project, DTComponentUUID: component,
			DTVulnerabilityUUID: "v", DTVulnSource: "NVD", DTVulnID: "CVE-2021-44228"}
	}
	id, _, err := st.UpsertFinding(ctx, obs("app", "c-app"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if again, _, _ := st.UpsertFinding(ctx, obs("image", "c-image"), nil); again != id {
		t.Fatalf("second project made finding %d, want %d", again, id)
	}
	refs, _ := st.FindingRefs(ctx, id)
	if len(refs) != 2 || refs[0].Project != "app" || refs[1].Project != "image" {
		t.Fatalf("refs = %+v", refs)
	}
	if cur, _ := st.CurrentRefs(ctx, id); len(cur) != 2 {
		t.Fatalf("current refs = %+v", cur)
	}
	n, err := st.ApplyState(ctx, DTKey{ProjectUUID: "app", ComponentUUID: "c-app", VulnerabilityUUID: "v"},
		finding.StateInProgress, map[string]any{"analysis_state": "IN_TRIAGE"})
	if err != nil || n != 1 {
		t.Fatalf("change in the first project: n=%d err=%v", n, err)
	}
	// A ref that names a different component does not match.
	if n, _ := st.ApplyState(ctx, DTKey{ProjectUUID: "app", ComponentUUID: "c-image", VulnerabilityUUID: "v"},
		finding.StateNotAffected, nil); n != 0 {
		t.Fatalf("mismatched ref changed %d findings", n)
	}
}

// TestRefsOutliveResolution: resolving a finding removes its sightings
// but keeps its refs, and a native observation records its own ref.
func TestRefsOutliveResolution(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	o := finding.Observation{Service: "storefront", Environment: "main", ComponentRef: "pkg:npm/lodash@4.17.15",
		VulnID: "CVE-2020-8203", Severity: finding.SeverityHigh,
		Source: finding.SourcePatchline, SourceProject: "storefront-api@main"}
	id, _, err := st.UpsertFinding(ctx, o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ResolveMissingIn(ctx, finding.SourcePatchline, "storefront-api@main", nil, nil); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFinding(ctx, id); f.State != string(finding.StateResolved) {
		t.Fatalf("state = %s", f.State)
	}
	refs, _ := st.FindingRefs(ctx, id)
	want := []finding.Ref{{Source: "patchline", Project: "storefront-api@main", Component: "pkg:npm/lodash@4.17.15", Vuln: "CVE-2020-8203"}}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("refs = %+v", refs)
	}
	if cur, _ := st.CurrentRefs(ctx, id); len(cur) != 0 {
		t.Fatalf("current refs of a resolved finding = %+v", cur)
	}

	// An explicit Ref wins over the derived one.
	o.Ref = finding.Ref{Source: "grype", Project: "img@sha256:1", Component: "pkg:npm/lodash@4.17.15", Vuln: "GHSA-p6mc"}
	if _, _, err := st.UpsertFinding(ctx, o, nil); err != nil {
		t.Fatal(err)
	}
	if refs, _ := st.FindingRefs(ctx, id); len(refs) != 2 || refs[0].Source != "grype" {
		t.Fatalf("refs = %+v", refs)
	}
}
