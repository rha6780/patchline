package impact

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/store"
)

const (
	log4jPkg = "org.apache.logging.log4j:log4j-core"
	log4j141 = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	log4j171 = "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
)

// setup stores three snapshots: storefront main (2.14.1, finding open),
// storefront prod (2.14.1, finding resolved by a later decision), billing
// main (2.17.1, not affected), plus an OSV record for Log4Shell.
func setup(t *testing.T) *store.Store {
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
	snap := func(name, version, service, purl string) {
		id := name + "@" + version
		v := "2.14.1"
		if purl == log4j171 {
			v = "2.17.1"
		}
		if err := st.TouchSourceProject(ctx, store.SourceProject{Source: finding.SourcePatchline, ProjectID: id, Name: name,
			Version: version, Service: service, Registered: true, Commit: "abc1234"}, true); err != nil {
			t.Fatal(err)
		}
		if err := st.ReplaceComponents(ctx, finding.SourcePatchline, id, []store.Component{
			{PURL: purl, Name: "log4j-core", Version: v, Ecosystem: "Maven", Package: log4jPkg},
			{PURL: "pkg:npm/lodash@4.17.21", Name: "lodash", Version: "4.17.21", Ecosystem: "npm", Package: "lodash"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	snap("storefront-api", "main", "storefront", log4j141)
	snap("storefront-api", "prod", "storefront", log4j141)
	snap("billing", "main", "billing", log4j171)
	if err := st.UpsertOSV(ctx, []store.OSVRecord{{ID: "GHSA-jfh8-c2jp-5v3q", Ecosystem: "Maven", Modified: "2025-01-01T00:00:00Z",
		Aliases: []string{"CVE-2021-44228"}, Summary: "Remote code injection in Log4j", Severity: finding.SeverityCritical,
		Affected: []store.OSVAffected{{Ecosystem: "Maven", Package: log4jPkg, Ranges: []store.OSVRange{
			{Introduced: "2.13.0", Fixed: "2.15.0"}, {Introduced: "2.0-beta9", Fixed: "2.3.1"}}}}}}); err != nil {
		t.Fatal(err)
	}
	obs := func(env string) finding.Observation {
		return finding.Observation{Service: "storefront", Registered: true, Environment: env, ComponentRef: log4j141,
			VulnID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, Severity: finding.SeverityCritical,
			Source: finding.SourcePatchline, SourceProject: "storefront-api@" + env}
	}
	if _, _, err := st.UpsertFinding(ctx, obs("main"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.UpsertFinding(ctx, obs("prod"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ResolveMissingIn(ctx, finding.SourcePatchline, "storefront-api@prod", nil, nil); err != nil {
		t.Fatal(err)
	}
	// Dependency-Track knows another service that Patchline has no SBOM for.
	if _, _, err := st.UpsertFinding(ctx, finding.Observation{Service: "legacy", Environment: "prod", ComponentRef: log4j141,
		VulnID: "CVE-2021-44228", Severity: finding.SeverityCritical, DTProjectUUID: "dt-1"}, nil); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestSearch(t *testing.T) {
	ctx := context.Background()
	st := setup(t)
	for _, tc := range []struct {
		q    Query
		want int
	}{
		{Query{Text: "log4j"}, 3},
		{Query{Text: "LOG4J", Version: "< 2.17.0"}, 2},
		{Query{Text: "log4j", Version: ">= 2.15.0, <= 2.17.1"}, 1},
		{Query{Text: "log4j", Version: "= 2.14.1"}, 2},
		{Query{Ecosystem: "npm"}, 3},
		{Query{Text: "%"}, 0},
		{Query{}, 0},
	} {
		got, err := Search(ctx, st, tc.q)
		if err != nil {
			t.Fatalf("%+v: %v", tc.q, err)
		}
		if len(got) != tc.want {
			t.Errorf("%+v: %d results, want %d", tc.q, len(got), tc.want)
		}
	}
	got, _ := Search(ctx, st, Query{Text: "log4j-core", Version: "< 2.15"})
	if got[0].Service != "storefront" || got[0].Environment != "main" || got[0].OpenFindings != 1 || got[0].Commit != "abc1234" {
		t.Errorf("first use = %+v", got[0])
	}
	if got[1].Environment != "prod" || got[1].OpenFindings != 0 {
		t.Errorf("prod use = %+v", got[1])
	}
	if _, err := Search(ctx, st, Query{Text: "x", Version: "<< 2"}); err == nil {
		t.Error("bad constraint accepted")
	}
}

func TestAnalyze(t *testing.T) {
	ctx := context.Background()
	st := setup(t)
	for _, asked := range []string{"CVE-2021-44228", "GHSA-jfh8-c2jp-5v3q"} {
		rep, err := Analyze(ctx, st, asked)
		if err != nil {
			t.Fatal(err)
		}
		if rep.ID != "CVE-2021-44228" || len(rep.Aliases) != 1 || rep.Severity != finding.SeverityCritical ||
			rep.Summary == "" || len(rep.Advisories) != 1 {
			t.Fatalf("%s: report = %+v", asked, rep)
		}
		if len(rep.Packages) != 1 || len(rep.Packages[0].Ranges) != 2 || rep.Packages[0].Ranges[0] != ">= 2.13.0, < 2.15.0" {
			t.Errorf("packages = %+v", rep.Packages)
		}
		// storefront main and prod are affected (prod's finding is closed),
		// billing runs a fixed version.
		if len(rep.Affected) != 2 || rep.Unaffected != 1 {
			t.Fatalf("affected = %d, unaffected = %d", len(rep.Affected), rep.Unaffected)
		}
		main, prod := rep.Affected[0], rep.Affected[1]
		if main.Environment != "main" || main.Fixed != "2.15.0" || main.Finding == nil || main.Finding.State != "new" {
			t.Errorf("main = %+v", main)
		}
		if prod.Finding == nil || prod.Finding.State != "resolved" {
			t.Errorf("prod = %+v", prod)
		}
		// Findings from every source, including Dependency-Track's for a
		// service without an SBOM in Patchline.
		if len(rep.Findings) != 3 {
			t.Errorf("findings = %d, want 3", len(rep.Findings))
		}
	}

	// Unknown to OSV: only the findings.
	rep, err := Analyze(ctx, st, "CVE-2099-0001")
	if err != nil || len(rep.Advisories) != 0 || len(rep.Affected) != 0 || len(rep.Findings) != 0 {
		t.Fatalf("unknown = %+v, %v", rep, err)
	}
}

func TestParseConstraint(t *testing.T) {
	r, err := ParseConstraint(">= 2.0, < 2.17.0")
	if err != nil || !r.Contains("2.14.1") || r.Contains("2.17.0") || r.Contains("1.9") {
		t.Fatalf("range = %+v, %v", r, err)
	}
	if r, _ := ParseConstraint("2.14.1"); r.Exact != "2.14.1" {
		t.Errorf("bare version = %+v", r)
	}
	for _, bad := range []string{"<", "< 1 < 2", ">=,"} {
		if _, err := ParseConstraint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
