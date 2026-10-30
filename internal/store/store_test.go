package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rha6780/patchline/internal/finding"
)

func TestOpenAndMigrate(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "sub", "patchline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	n, err := Migrate(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("expected at least one migration to run")
	}

	// Running again is a no-op.
	if n, err := Migrate(ctx, db); err != nil || n != 0 {
		t.Fatalf("second migrate: n=%d err=%v, want 0 nil", n, err)
	}

	for _, table := range []string{"webhook_inbox", "findings", "finding_events"} {
		var name string
		err := db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Errorf("table %s missing: %v", table, err)
		}
	}

	var fk int
	if err := db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Errorf("foreign_keys = %d (err %v), want 1", fk, err)
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "patchline.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	return New(db)
}

func TestFindingSearchFilters(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	add := func(env, ref, purl, name, vuln, sev string, aliases ...string) int64 {
		project := "app@" + env
		_ = s.TouchSourceProject(ctx, SourceProject{Source: "patchline", ProjectID: project, Name: "app", Version: env,
			Service: "app", Registered: true, Ref: ref}, true)
		id, _, err := s.UpsertFinding(ctx, finding.Observation{Service: "app", Registered: true, Repository: "acme/app",
			Environment: env, ComponentRef: purl, ComponentName: name, VulnID: vuln, Aliases: aliases, Severity: sev,
			Title: "Remote code injection", Source: "patchline", SourceProject: project}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	log4j := add("main", "refs/heads/main", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "log4j-core", "CVE-2021-44228", "critical", "GHSA-jfh8-c2jp-5v3q")
	add("prod", "refs/tags/v1.4.0", "pkg:deb/debian/libssl1.1@1.1.1n", "libssl1.1", "CVE-2023-5678", "medium")
	// KEV made the libssl finding critical in effect.
	open, _ := s.OpenFindingsForSLA(ctx)
	for _, f := range open {
		if f.VulnID == "CVE-2023-5678" {
			_ = s.UpdateSLA(ctx, SLAUpdate{FindingID: f.ID, EffectiveSeverity: "critical", KEV: true, Silent: true}, f.Finding)
		}
	}
	for _, tc := range []struct {
		f    FindingFilter
		want int
	}{
		{FindingFilter{Query: "cve-2021-44228"}, 1},
		{FindingFilter{Query: "GHSA-JFH8"}, 1},
		{FindingFilter{Query: "openssl"}, 0},
		{FindingFilter{Query: "libssl"}, 1},
		{FindingFilter{Query: "remote code"}, 2},
		{FindingFilter{Query: "%"}, 0},
		{FindingFilter{Branch: "main"}, 1},
		{FindingFilter{Branch: "refs/heads/main"}, 1},
		{FindingFilter{Branch: "v1.4.0"}, 1},
		{FindingFilter{Branch: "develop"}, 0},
		{FindingFilter{Repository: "acme/app"}, 2},
		{FindingFilter{Repository: "acme/other"}, 0},
		{FindingFilter{Severity: "critical"}, 2},
		{FindingFilter{Severity: "medium"}, 0},
		{FindingFilter{Severity: "critical", Branch: "main", Query: "log4j"}, 1},
	} {
		got, err := s.ListFindings(ctx, tc.f)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != tc.want {
			t.Errorf("%+v: %d findings, want %d", tc.f, len(got), tc.want)
		}
	}
	projects, _ := s.ServiceProjects(ctx, "app")
	if len(projects) != 2 || projects[0].Branch != "main" || projects[1].Branch != "v1.4.0" || projects[0].Repository != "acme/app" {
		t.Errorf("projects = %+v", projects)
	}
	branches, _ := s.Branches(ctx)
	if len(branches) != 2 {
		t.Errorf("branches = %v", branches)
	}
	_ = log4j
}
