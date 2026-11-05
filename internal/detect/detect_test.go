package detect

import (
	"context"
	"testing"

	"github.com/rha6780/patchline/internal/store"
)

type engine map[string][]Match

func (engine) Ready(context.Context) (bool, error) { return true, nil }
func (e engine) MatchAll(context.Context, []store.Component) (map[string][]Match, error) {
	return e, nil
}

// TestCombinedKeepsCVEsOfOneAdvisory: Trivy names Debian CVEs with the
// advisory that fixes them (DLA-3942-1 fixes CVE-2023-5678 and
// CVE-2024-0727). Both are findings; a shared alias must not merge them,
// or whichever comes first wins and the other flips between resolved and
// reopened from scan to scan.
func TestCombinedKeepsCVEsOfOneAdvisory(t *testing.T) {
	const ssl = "pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u4"
	const log4j = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	osv := engine{log4j: {{ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}, Engine: "osv"}}}
	trivy := engine{
		ssl: {
			{ID: "CVE-2023-5678", Aliases: []string{"DLA-3942-1"}, Engine: "trivy"},
			{ID: "CVE-2024-0727", Aliases: []string{"DLA-3942-1"}, Engine: "trivy"},
		},
		log4j: {{ID: "CVE-2021-44228", Engine: "trivy"}},
	}
	got, err := Combined{osv, trivy}.MatchAll(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got[ssl]) != 2 {
		t.Errorf("libssl matches = %+v, want both CVEs", got[ssl])
	}
	// The same vulnerability from two engines is reported once, by the first.
	if len(got[log4j]) != 1 || got[log4j][0].Engine != "osv" {
		t.Errorf("log4j matches = %+v, want the OSV one only", got[log4j])
	}
}
