package trivy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/rha6780/patchline/internal/store"
)

// fakeServer records PutBlob requests and answers Scan with one
// vulnerability per package.
type fakeServer struct {
	mu      sync.Mutex
	blobs   map[string]blobInfo
	deleted []string
	token   string
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Trivy-Token") != f.token {
		http.Error(w, `{"code":"unauthenticated","msg":"invalid token"}`, http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/twirp/trivy.cache.v1.Cache/PutBlob":
		var req struct {
			DiffID   string   `json:"diff_id"`
			BlobInfo blobInfo `json:"blob_info"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.blobs[req.DiffID] = req.BlobInfo
		_, _ = w.Write([]byte("{}"))
	case "/twirp/trivy.scanner.v1.Scanner/Scan":
		var req struct {
			BlobIDs []string `json:"blob_ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		b := f.blobs[req.BlobIDs[0]]
		var vulns []vulnerability
		add := func(p pkg, fixed string) {
			vulns = append(vulns, vulnerability{VulnerabilityID: "CVE-" + p.Name, VendorIDs: []string{"GHSA-" + p.Name},
				InstalledVersion: p.Version, FixedVersion: fixed, Severity: "HIGH", Title: "t",
				PkgIdentifier: pkgIdentifier{PURL: "re-encoded", BOMRef: p.Identifier.BOMRef}})
		}
		for _, pi := range b.PackageInfos {
			for _, p := range pi.Packages {
				add(p, p.Version+".1")
			}
		}
		for _, a := range b.Applications {
			for _, p := range a.Packages {
				add(p, "1.0.0, 9.9.9")
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"vulnerabilities": vulns}}})
	case "/twirp/trivy.cache.v1.Cache/DeleteBlobs":
		var req struct {
			BlobIDs []string `json:"blob_ids"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.deleted = append(f.deleted, req.BlobIDs...)
		_, _ = w.Write([]byte("{}"))
	default:
		http.NotFound(w, r)
	}
}

func TestMatchAll(t *testing.T) {
	fs := &fakeServer{blobs: map[string]blobInfo{}, token: "tok"}
	srv := httptest.NewServer(fs)
	defer srv.Close()
	comps := []store.Component{
		{PURL: "pkg:deb/debian/libssl1.1@1:1.1.1n-0+deb11u3?arch=amd64&distro=debian-11.6", SrcName: "openssl", SrcVersion: "1.1.1n-0+deb11u3"},
		{PURL: "pkg:apk/alpine/busybox@1.36.1-r0?distro=alpine-3.18.0"},
		{PURL: "pkg:rpm/redhat/bash@5.1.8-6.el9?distro=rhel-9.2&epoch=2"},
		{PURL: "pkg:deb/debian/nodistro@1.0-1"},
		{PURL: "pkg:maven/org.example/lib@2.0.0"},
	}

	// OS packages only by default.
	e := &Engine{URL: srv.URL, Token: "tok"}
	m, err := e.MatchAll(context.Background(), comps)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs.blobs) != 3 || len(fs.deleted) != 3 {
		t.Fatalf("blobs = %d, deleted = %d (one per OS release)", len(fs.blobs), len(fs.deleted))
	}
	var deb, apk, rpm blobInfo
	for _, b := range fs.blobs {
		switch b.OS.Family {
		case "debian":
			deb = b
		case "alpine":
			apk = b
		case "redhat":
			rpm = b
		}
		if len(b.Applications) != 0 {
			t.Error("language packages sent without All")
		}
	}
	d := deb.PackageInfos[0].Packages[0]
	if deb.OS.Name != "11.6" || d.Name != "libssl1.1" || d.Epoch != 1 || d.Version != "1.1.1n" || d.Release != "0+deb11u3" ||
		d.SrcName != "openssl" || d.SrcVersion != "1.1.1n" || d.SrcRelease != "0+deb11u3" || d.Arch != "amd64" {
		t.Errorf("deb package = %+v", d)
	}
	if a := apk.PackageInfos[0].Packages[0]; a.Version != "1.36.1-r0" || a.Release != "" || a.SrcName != "busybox" {
		t.Errorf("apk package = %+v", a)
	}
	if r := rpm.PackageInfos[0].Packages[0]; rpm.OS.Name != "9.2" || r.Epoch != 2 || r.Version != "5.1.8" || r.Release != "6.el9" {
		t.Errorf("rpm package = %+v (%+v)", r, rpm.OS)
	}
	ms := m[comps[0].PURL]
	if len(ms) != 1 || ms[0].ID != "CVE-libssl1.1" || ms[0].Severity != "high" || ms[0].Engine != "trivy" ||
		ms[0].Fixed != "1.1.1n.1" || ms[0].Aliases[0] != "GHSA-libssl1.1" {
		t.Errorf("deb match = %+v", ms)
	}
	if len(m[comps[3].PURL]) != 0 || len(m[comps[4].PURL]) != 0 {
		t.Error("matched a package without distro, or a language package without All")
	}

	// All: language packages ride on the first blob; the fixed version is
	// the lowest one above the installed version.
	fs.blobs = map[string]blobInfo{}
	e.All = true
	m, err = e.MatchAll(context.Background(), comps[4:])
	if err != nil {
		t.Fatal(err)
	}
	if len(fs.blobs) != 1 {
		t.Fatalf("blobs = %d", len(fs.blobs))
	}
	for _, b := range fs.blobs {
		if b.OS != nil || len(b.Applications) != 1 || b.Applications[0].Type != "jar" || b.Applications[0].Packages[0].Name != "org.example:lib" {
			t.Errorf("app blob = %+v", b)
		}
	}
	if ms := m[comps[4].PURL]; len(ms) != 1 || ms[0].Fixed != "9.9.9" || ms[0].Range != "= 2.0.0" {
		t.Errorf("maven match = %+v", ms)
	}

	// A wrong token fails the analysis (it is retried; nothing resolves).
	e.Token = "wrong"
	if _, err := e.MatchAll(context.Background(), comps[:1]); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("wrong token: %v", err)
	}
}
