package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/store"
)

func setup(t *testing.T) (*UI, *store.Store) {
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
	doc := "services:\n  - name: storefront\n    owners: [alice@example.com]\n    slack_channel: '#sf'\n    exposure: internet\n" +
		"    repositories: [{repo: acme/storefront-api}, {repo: acme/never-scanned}]\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	u, err := New(Options{Store: st, Inventory: inv, DTUIURL: "http://dt.local", Version: "test",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return time.Now() }})
	if err != nil {
		t.Fatal(err)
	}

	obs := func(env, sev string) finding.Observation {
		return finding.Observation{Service: "storefront", Registered: true, Repository: "acme/storefront-api", Environment: env,
			ComponentRef: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", ComponentName: "org.apache.logging.log4j/log4j-core",
			ComponentVersion: "2.14.1", VulnID: "CVE-2021-44228", Aliases: []string{"GHSA-jfh8-c2jp-5v3q"}, Severity: sev,
			Title: "Log4Shell <b>", DTProjectUUID: "p-" + env}
	}
	mainID, _, _ := st.UpsertFinding(ctx, obs("main", finding.SeverityCritical), map[string]any{})
	_, _, _ = st.UpsertFinding(ctx, obs("prod", finding.SeverityCritical), map[string]any{})
	_, _ = st.LinkPullRequest(ctx, store.PullRequestLink{FindingID: mainID, Repository: "acme/storefront-api", Number: 12,
		URL: "https://git/pulls/12", Title: "Update log4j", Package: "log4j-core", FromVersion: "2.14.1", ToVersion: "2.17.1",
		Verdict: store.VerdictFixes, VerdictDetail: "outside < 2.15.0"})
	_, _ = st.ClosePullRequest(ctx, "acme/storefront-api", 12, true, "3f2a9c1e0b7d4a6f")
	_, _ = st.ResolveMissing(ctx, "p-main", nil, map[string]any{"commit": "3f2a9c1e0b7d4a6f"})

	stray := obs("default", finding.SeverityLow)
	stray.Service, stray.Registered, stray.Repository = "stray-app", false, ""
	_, _, _ = st.UpsertFinding(ctx, stray, nil)
	_ = st.TouchSourceProject(ctx, store.SourceProject{Source: "dependencytrack", ProjectID: "p-main", Name: "storefront-api",
		Version: "main", Service: "storefront", Registered: true, Commit: "3f2a9c1e0b7d4a6f", Ref: "refs/heads/main"}, true)
	return u, st
}

func get(t *testing.T, h http.Handler, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

func TestPages(t *testing.T) {
	u, _ := setup(t)
	tests := []struct {
		path string
		want []string
	}{
		{"/", []string{"Open findings", "storefront", "stray-app", "not in inventory", "Recently resolved", "CVE-2021-44228"}},
		{"/findings?open=1", []string{"CVE-2021-44228", "prod", "unregistered"}},
		{"/findings?severity=critical&state=resolved", []string{"main", "Resolved"}},
		{"/findings/1", []string{"Log4Shell &lt;b&gt;", "Timeline", "Detected by Dependency-Track", "Fix PR merged",
			"acme/storefront-api#12", "leaves the affected range", "no longer reported for the latest BOM",
			"http://dt.local/projects/p-main/findings", "alice@example.com"}},
		{"/services/storefront", []string{"Findings by environment", "<th>main</th>", "<th>prod</th>", "class=\"gap\"",
			"fixed in one environment but still open in another", "acme/never-scanned"}},
		{"/services/stray-app", []string{"not mapped to a service"}},
		{"/integrations", []string{"storefront-api", "3f2a9c1e0b7d", "refs/heads/main", "never-scanned", "Inventory projects without a BOM"}},
		{"/static/style.css", []string{"--crit"}},
	}
	for _, tc := range tests {
		code, body := get(t, u, tc.path)
		if code != http.StatusOK {
			t.Errorf("%s: status %d\n%s", tc.path, code, body)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s: missing %q", tc.path, w)
			}
		}
	}
}

func TestNotFound(t *testing.T) {
	u, _ := setup(t)
	for _, p := range []string{"/findings/999", "/findings/abc", "/services/nope", "/nope"} {
		if code, _ := get(t, u, p); code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, code)
		}
	}
}

func TestEmptyOverview(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(ctx, filepath.Join(t.TempDir(), "p.db"))
	defer db.Close()
	_, _ = store.Migrate(ctx, db)
	u, err := New(Options{Store: store.New(db)})
	if err != nil {
		t.Fatal(err)
	}
	code, body := get(t, u, "/")
	if code != http.StatusOK || !strings.Contains(body, "Connect Dependency-Track") {
		t.Fatalf("empty overview: %d", code)
	}
	if code, body := get(t, u, "/integrations"); code != http.StatusOK || !strings.Contains(body, "No project has reported yet") {
		t.Fatalf("empty integrations: %d %s", code, body)
	}
}

func TestRich(t *testing.T) {
	got := string(rich("merged https://git/pulls/12 (commit `3f2a9c` <x>)"))
	want := `merged <a href="https://git/pulls/12">https://git/pulls/12</a> (commit <code>3f2a9c</code> &lt;x&gt;)`
	if got != want {
		t.Errorf("rich:\n got %s\nwant %s", got, want)
	}
	if got := string(rich("`<script>`")); got != "<code>&lt;script&gt;</code>" {
		t.Errorf("code escaping: %s", got)
	}
}
