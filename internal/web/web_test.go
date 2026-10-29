package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
		{"/integrations", []string{`href="/docs/integrations"`}},
		{"/docs/integrations", []string{"Integrations guide", "Dependency-Track", "OpenCVE", "Planned",
			"<code>NEW_VULNERABLE_DEPENDENCY</code>", "<code>PATCHLINE_DT_URL</code>", "https://docs.opencve.io/", "CISA KEV",
			"blob/main/docs/integrations/sbom-ci.md"}},
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

func TestFooter(t *testing.T) {
	u, _ := setup(t)
	for _, p := range []string{"/", "/findings", "/integrations", "/docs/integrations"} {
		_, body := get(t, u, p)
		for _, w := range []string{`<footer class="site">`, `href="/docs/integrations"`, "https://docs.opencve.io/",
			"https://github.com/rha6780/patchline", "Not affiliated with OWASP"} {
			if !strings.Contains(body, w) {
				t.Errorf("%s footer: missing %q", p, w)
			}
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/integrations", nil)
	req.Header.Set("Accept-Language", "ko-KR")
	u.ServeHTTP(rec, req)
	for _, w := range []string{"연동 가이드", "예정", "docs/integrations/renovate.ko.md", "docs/README.ko.md", "OWASP 및 Dependency-Track 프로젝트와 무관"} {
		if !strings.Contains(rec.Body.String(), w) {
			t.Errorf("ko guide: missing %q", w)
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

func TestDueDisplay(t *testing.T) {
	ctx := context.Background()
	u, st := setup(t)
	prod, err := st.ListFindings(ctx, store.FindingFilter{Service: "storefront", Environment: "prod"})
	if err != nil || len(prod) != 1 {
		t.Fatalf("prod = %+v %v", prod, err)
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := st.UpdateSLA(ctx, store.SLAUpdate{FindingID: prod[0].ID, KEV: true, EffectiveSeverity: "critical",
		Reasons: []string{"in CISA KEV"}, Due: &past}, prod[0]); err != nil {
		t.Fatal(err)
	}
	for path, wants := range map[string][]string{
		"/":                     {"Overdue", `class="tile alert"`, "KEV", "overdue by 2 days"},
		"/findings?due=overdue": {"CVE-2021-44228", "overdue by"},
		"/findings?due=week":    {"CVE-2021-44228"},
		"/findings/" + strconv.FormatInt(prod[0].ID, 10): {"CISA KEV", "overdue by", "in CISA KEV", "Due date updated"},
	} {
		code, body := get(t, u, path)
		if code != 200 {
			t.Errorf("%s: %d", path, code)
		}
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("%s: missing %q", path, w)
			}
		}
	}
}

func TestPreferences(t *testing.T) {
	u, _ := setup(t)

	// Language from Accept-Language.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Language", "ko-KR,ko;q=0.9,en;q=0.8")
	rec := httptest.NewRecorder()
	u.ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, want := range []string{`<html lang="ko">`, "열린 Finding", "서비스별 열린 Finding", "조치 필요", "한국어"} {
		if !strings.Contains(body, want) {
			t.Errorf("ko via header: missing %q", want)
		}
	}

	// /prefs sets cookies and redirects back; unsafe "next" values go home.
	for next, want := range map[string]string{"/findings?open=1": "/findings?open=1", "//evil.example": "/", "https://evil.example": "/"} {
		rec = httptest.NewRecorder()
		u.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/prefs?lang=ko&theme=dark&next="+url.QueryEscape(next), nil))
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
			t.Errorf("next=%q: %d %q", next, rec.Code, rec.Header().Get("Location"))
		}
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies = %v", cookies)
	}

	// Cookies win over the header.
	req = httptest.NewRequest(http.MethodGet, "/findings/1", nil)
	req.Header.Set("Accept-Language", "en")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	u.ServeHTTP(rec, req)
	body = rec.Body.String()
	for _, want := range []string{`<html lang="ko" data-theme="dark">`, "타임라인", "Dependency-Track에서 탐지", "수정 PR 병합", "최신 BOM에서 더 이상 보고되지 않음", "✅ 해결"} {
		if !strings.Contains(body, want) {
			t.Errorf("ko via cookie: missing %q", want)
		}
	}

	// Invalid values are ignored.
	rec = httptest.NewRecorder()
	u.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/prefs?lang=xx&theme=neon", nil))
	if len(rec.Result().Cookies()) != 0 {
		t.Error("invalid preferences should not set cookies")
	}
}

func TestEveryPageInKorean(t *testing.T) {
	u, _ := setup(t)
	for _, p := range []string{"/", "/findings?open=1", "/findings/1", "/services/storefront", "/services/stray-app", "/integrations"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.AddCookie(&http.Cookie{Name: cookieLang, Value: "ko"})
		rec := httptest.NewRecorder()
		u.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("%s: %d", p, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "ui.") {
			t.Errorf("%s: untranslated key in output", p)
		}
	}
}

func TestFindingsFilters(t *testing.T) {
	u, _ := setup(t)
	_, body := get(t, u, "/findings?open=1&service=storefront&bogus=1")
	for _, want := range []string{
		`<a class="chip" href="/findings?open=1" >Open</a>`,       // preset not active: extra filter applied
		`<option value="storefront" selected>storefront</option>`, // service select from facets
		`<option value="stray-app" >stray-app</option>`,           // other services listed
		`<option value="prod" >prod</option>`,                     // environments listed
		`href="/findings?open=1" title="Remove filter: Service"`,  // removing service keeps open
		`href="/findings?service=storefront" title="Remove filter: open only"`,
		"Active filters", "Clear all",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "bogus=1&amp;") || strings.Contains(body, `title="Remove filter: bogus"`) {
		t.Error("unknown parameters must be dropped from filter links")
	}

	_, body = get(t, u, "/findings?due=overdue")
	if !strings.Contains(body, `href="/findings?due=overdue" aria-current="true"`) {
		t.Error("overdue preset should be active")
	}
	_, body = get(t, u, "/findings")
	if !strings.Contains(body, `href="/findings" aria-current="true"`) || strings.Contains(body, "Active filters") {
		t.Error("all preset active, no active filters")
	}
}
