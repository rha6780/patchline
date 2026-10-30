package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/purl"
	"github.com/rha6780/patchline/internal/store"
)

const log4shell = `{"id":"GHSA-jfh8-c2jp-5v3q","modified":"2025-10-22T19:37:02Z","aliases":["CVE-2021-44228"],
 "summary":"Remote code injection in Log4j","database_specific":{"severity":"CRITICAL"},
 "affected":[
  {"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},
   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.13.0"},{"fixed":"2.15.0"}]},
             {"type":"ECOSYSTEM","events":[{"introduced":"2.0-beta9"},{"fixed":"2.3.1"},{"introduced":"2.4"},{"fixed":"2.12.2"}]},
             {"type":"GIT","repo":"https://github.com/apache/logging-log4j2","events":[{"introduced":"0"}]}]},
  {"package":{"ecosystem":"npm","name":"other"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`

func TestParse(t *testing.T) {
	r, err := Parse([]byte(log4shell), purl.Maven)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "GHSA-jfh8-c2jp-5v3q" || r.Severity != finding.SeverityCritical || len(r.Affected) != 1 {
		t.Fatalf("record = %+v", r)
	}
	a := r.Affected[0]
	if a.Package != "org.apache.logging.log4j:log4j-core" || len(a.Ranges) != 3 ||
		a.Ranges[0] != (store.OSVRange{Introduced: "2.13.0", Fixed: "2.15.0"}) ||
		a.Ranges[2] != (store.OSVRange{Introduced: "2.4", Fixed: "2.12.2"}) {
		t.Fatalf("affected = %+v", a)
	}

	// No curated severity: the CVSS v3 vector decides; open-ended ranges stay open.
	r, _ = Parse([]byte(`{"id":"PYSEC-1","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"}],
	  "affected":[{"package":{"ecosystem":"PyPI","name":"Django_Thing"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"last_affected":"1.4"}]}],"versions":["1.0","1.4"]}]}`), purl.PyPI)
	if r.Severity != finding.SeverityMedium || r.Affected[0].Package != "django-thing" ||
		r.Affected[0].Ranges[0] != (store.OSVRange{Introduced: "1.0", LastAffected: "1.4"}) {
		t.Fatalf("pypi record = %+v", r)
	}
	if _, err := Parse([]byte(`{"summary":"no id"}`), purl.NPM); err == nil {
		t.Error("record without id accepted")
	}
}

func TestCVSS3(t *testing.T) {
	for vector, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N": 3.3,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N": 5.4,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	} {
		got, err := CVSS3BaseScore(vector)
		if err != nil || got != want {
			t.Errorf("%s = %v (%v), want %v", vector, got, err, want)
		}
	}
	for _, bad := range []string{"CVSS:2.0/AV:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"} {
		if _, err := CVSS3BaseScore(bad); err == nil {
			t.Errorf("%s: want an error", bad)
		}
	}
}

type fakeDB map[string][]store.OSVCandidate

func (f fakeDB) OSVCandidates(_ context.Context, eco, pkg string) ([]store.OSVCandidate, error) {
	return f[eco+" "+pkg], nil
}

func TestMatchComponent(t *testing.T) {
	r, _ := Parse([]byte(log4shell), purl.Maven)
	db := fakeDB{"Maven org.apache.logging.log4j:log4j-core": {{ID: r.ID, Aliases: r.Aliases, Severity: r.Severity, Ranges: r.Affected[0].Ranges}},
		"Go github.com/x/y": {{ID: "GO-1", Ranges: []store.OSVRange{{Introduced: "0", Fixed: "1.2.0"}}}},
		"PyPI listed":       {{ID: "PYSEC-2", Versions: []string{"0.9"}, Ranges: []store.OSVRange{{Introduced: "0", Fixed: "1.0"}}}},
		"PyPI listed-only":  {{ID: "PYSEC-3", Versions: []string{"3.0", "3.1"}}},
	}
	comp := func(eco, pkg, v string) store.Component {
		return store.Component{Ecosystem: eco, Package: pkg, Version: v}
	}
	for _, tc := range []struct {
		c     store.Component
		ids   int
		rng   string
		fixed string
	}{
		{comp(purl.Maven, "org.apache.logging.log4j:log4j-core", "2.14.1"), 1, ">= 2.13.0, < 2.15.0", "2.15.0"},
		{comp(purl.Maven, "org.apache.logging.log4j:log4j-core", "2.11.0"), 1, ">= 2.4, < 2.12.2", "2.12.2"},
		{comp(purl.Maven, "org.apache.logging.log4j:log4j-core", "2.17.1"), 0, "", ""},
		{comp(purl.Maven, "org.apache.logging.log4j:log4j-core", "2.12.2"), 0, "", ""},
		{comp(purl.Go, "github.com/x/y", "v1.1.9"), 1, "< 1.2.0", "1.2.0"},
		{comp(purl.Go, "github.com/x/y", "v1.2.0"), 0, "", ""},
		{comp(purl.PyPI, "listed", "0.9"), 1, "< 1.0", "1.0"},
		{comp(purl.PyPI, "listed-only", "3.1"), 1, "= 3.1", ""},
		{comp("", "", "1.0"), 0, "", ""},
	} {
		ms, err := MatchComponent(context.Background(), db, tc.c)
		if err != nil {
			t.Fatal(err)
		}
		if len(ms) != tc.ids || (tc.ids > 0 && (ms[0].Range != tc.rng || ms[0].Fixed != tc.fixed)) {
			t.Errorf("%+v: %+v", tc.c, ms)
		}
	}
}

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

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, _ := zw.Create(name)
		_, _ = io.WriteString(w, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSync(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	var fulls, singles atomic.Int32
	modified := "" // modified_id.csv
	records := map[string]string{"GHSA-jfh8-c2jp-5v3q": log4shell}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/Maven/all.zip":
			fulls.Add(1)
			files := map[string]string{}
			for id, body := range records {
				files[id+".json"] = body
			}
			_, _ = w.Write(zipOf(t, files))
		case r.URL.Path == "/Maven/modified_id.csv":
			_, _ = io.WriteString(w, modified)
		case strings.HasPrefix(r.URL.Path, "/Maven/"):
			singles.Add(1)
			body, ok := records[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/Maven/"), ".json")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	clock := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	s := &Syncer{Store: st, BaseURL: srv.URL, Ecosystems: []string{purl.Maven}, TempDir: t.TempDir(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return clock }}
	e := Engine{DB: st, Syncer: s}
	if ready, _ := e.Ready(ctx); ready {
		t.Fatal("ready before the first sync")
	}

	// First sync: the full export.
	if n, err := s.Sync(ctx); err != nil || n != 1 || fulls.Load() != 1 {
		t.Fatalf("full sync: %d %v (fulls %d)", n, err, fulls.Load())
	}
	if ready, _ := e.Ready(ctx); !ready {
		t.Fatal("not ready after sync")
	}
	c := store.Component{Ecosystem: purl.Maven, Package: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"}
	if ms := matchOne(t, e, c); len(ms) != 1 || ms[0].Severity != finding.SeverityCritical {
		t.Fatalf("match after full sync: %+v", ms)
	}

	// Later: only records modified since then, newest first. A withdrawn
	// record stops matching.
	records["GHSA-new"] = `{"id":"GHSA-new","modified":"2026-10-30T05:00:00Z","affected":[{"package":{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.17.0"}]}]}]}`
	records["GHSA-jfh8-c2jp-5v3q"] = strings.Replace(log4shell, `"modified"`, `"withdrawn":"2026-10-30T04:00:00Z","modified"`, 1)
	modified = "2026-10-30T05:00:00Z,GHSA-new\n2026-10-30T04:00:00Z,GHSA-jfh8-c2jp-5v3q\n2026-10-29T00:00:00Z,GHSA-old\n"
	clock = clock.Add(6 * time.Hour)
	if n, err := s.Sync(ctx); err != nil || n != 2 || fulls.Load() != 1 || singles.Load() != 2 {
		t.Fatalf("incremental sync: %d %v (fulls %d, singles %d)", n, err, fulls.Load(), singles.Load())
	}
	ms := matchOne(t, e, c)
	if len(ms) != 1 || ms[0].ID != "GHSA-new" {
		t.Fatalf("match after incremental sync: %+v", ms)
	}

	// Too many changes: the full export again.
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, fmt.Sprintf("2026-10-30T07:00:0%dZ,GHSA-x%d", i, i))
	}
	modified = strings.Join(lines, "\n")
	s.IncrementalLimit = 3
	clock = clock.Add(6 * time.Hour)
	if _, err := s.Sync(ctx); err != nil || fulls.Load() != 2 {
		t.Fatalf("fallback to full: %v (fulls %d)", err, fulls.Load())
	}
	if n, _ := st.OSVCount(ctx, purl.Maven); n != 1 {
		t.Errorf("live records after full sync = %d", n)
	}
}

func TestSyncFailureKeepsData(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	_ = st.UpsertOSV(ctx, []store.OSVRecord{{ID: "X-1", Ecosystem: purl.NPM, Modified: "2026-01-01T00:00:00Z"}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) }))
	defer srv.Close()
	s := &Syncer{Store: st, BaseURL: srv.URL, Ecosystems: []string{purl.NPM}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if _, err := s.Sync(ctx); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("sync = %v", err)
	}
	if n, _ := st.OSVCount(ctx, purl.NPM); n != 1 {
		t.Errorf("records after a failed sync = %d", n)
	}
	if ready, _ := s.Ready(ctx); ready {
		t.Error("ready after a failed first sync")
	}
}

func matchOne(t *testing.T, e Engine, c store.Component) []Match {
	t.Helper()
	c.PURL = "pkg:test/" + c.Package
	m, err := e.MatchAll(context.Background(), []store.Component{c})
	if err != nil {
		t.Fatal(err)
	}
	return m[c.PURL]
}
