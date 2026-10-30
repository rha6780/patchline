package trivy

import (
	"context"
	"os"
	"testing"

	"github.com/rha6780/patchline/internal/store"
)

// TestServer runs against a real Trivy server when PATCHLINE_TRIVY_TEST_URL
// is set (and PATCHLINE_TRIVY_TEST_TOKEN, if it has one).
func TestServer(t *testing.T) {
	url := os.Getenv("PATCHLINE_TRIVY_TEST_URL")
	if url == "" {
		t.Skip("PATCHLINE_TRIVY_TEST_URL not set")
	}
	e := &Engine{URL: url, Token: os.Getenv("PATCHLINE_TRIVY_TEST_TOKEN"), All: true}
	comps := []store.Component{
		{PURL: "pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u3?arch=amd64&distro=debian-11.6", SrcName: "openssl", SrcVersion: "1.1.1n-0+deb11u3"},
		{PURL: "pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u3?arch=amd64&distro=debian-11.6"},
		{PURL: "pkg:apk/alpine/busybox@1.36.1-r0?arch=x86_64&distro=alpine-3.18.0"},
		{PURL: "pkg:deb/debian/zlib1g@1:1.2.11.dfsg-2+deb11u1?arch=amd64&distro=debian-11.6&upstream=zlib"},
		{PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{PURL: "pkg:deb/debian/openssl@1.1.1n-0+deb11u3"}, // no distro: skipped
	}
	m, err := e.MatchAll(context.Background(), comps)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range comps {
		ms := m[c.PURL]
		sample := ""
		if len(ms) > 0 {
			sample = ms[0].ID + " " + ms[0].Severity + " " + ms[0].Range + " fixed=" + ms[0].Fixed
		}
		t.Logf("%-90s %3d  %s", c.PURL, len(ms), sample)
	}
}
