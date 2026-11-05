package dependencytrack

import (
	"context"
	"strings"
	"testing"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/source"
	"github.com/rha6780/patchline/internal/store"
)

var log4shell = VulnerabilityDetail{
	VulnID: "GHSA-jfh8-c2jp-5v3q", Source: "GITHUB",
	AffectedComponents: []AffectedComponent{{
		IdentityType: "PURL", Identity: "pkg:maven/org.apache.logging.log4j/log4j-core",
		VersionType: "RANGE", VersionStartIncluding: "2.0-beta9", VersionEndExcluding: "2.15.0",
	}},
}

func TestJudge(t *testing.T) {
	purl := "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	tests := []struct {
		to      string
		detail  VulnerabilityDetail
		want    string
		snippet string
	}{
		{"2.17.1", log4shell, store.VerdictFixes, "outside the affected range >= 2.0-beta9, < 2.15.0"},
		{"2.14.2", log4shell, store.VerdictInsufficient, "still in the affected range"},
		{"2.17.1", VulnerabilityDetail{PatchedVersions: "2.15.0"}, store.VerdictFixes, "patched version 2.15.0"},
		{"2.14.9", VulnerabilityDetail{PatchedVersions: "2.15.0"}, store.VerdictInsufficient, "< patched"},
		{"2.17.1", VulnerabilityDetail{PatchedVersions: ">= 2.15.0"}, store.VerdictUnknown, "no affected version range"},
		{"2.17.1", VulnerabilityDetail{AffectedComponents: []AffectedComponent{{
			IdentityType: "PURL", Identity: "pkg:maven/other/lib", VersionType: "RANGE", VersionEndExcluding: "9"}}},
			store.VerdictUnknown, "no affected version range"},
	}
	for _, tc := range tests {
		got, detail := Judge(purl, tc.to, tc.detail)
		if got != tc.want || !strings.Contains(detail, tc.snippet) {
			t.Errorf("Judge(%s) = %s %q, want %s containing %q", tc.to, got, detail, tc.want, tc.snippet)
		}
	}
	if got := purlBase("pkg:deb/debian/openssl@3.0.11?arch=amd64"); got != "pkg:deb/debian/openssl" {
		t.Errorf("purlBase = %q", got)
	}
}

type fakeVulns struct{ asked []string }

func (f *fakeVulns) Vulnerability(_ context.Context, source, id string) (VulnerabilityDetail, error) {
	f.asked = append(f.asked, source+"/"+id)
	return log4shell, nil
}

// TestVerdict reads the ranges of the vulnerability as the finding's
// Dependency-Track ref names it, and stays out of findings it does not
// report.
func TestVerdict(t *testing.T) {
	ctx := context.Background()
	f := store.Finding{ID: 1, ComponentRef: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", VulnID: "CVE-2021-44228"}
	vulns := &fakeVulns{}
	a := &Adapter{Vulnerabilities: vulns}
	refs := []finding.Ref{
		{Source: "patchline", Project: "storefront-api@main", Component: f.ComponentRef, Vuln: "CVE-2021-44228"},
		{Source: Name, Project: "p", Component: "c", Vuln: "v", VulnSource: "GITHUB", VulnName: "GHSA-jfh8-c2jp-5v3q"},
	}
	if v, d, err := a.Verdict(ctx, f, refs, "2.17.1"); err != nil || v != store.VerdictFixes {
		t.Fatalf("verdict = %s %q %v", v, d, err)
	}
	if len(vulns.asked) != 1 || vulns.asked[0] != "GITHUB/GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("asked %v", vulns.asked)
	}
	if v, _, _ := a.Verdict(ctx, f, refs[:1], "2.17.1"); v != store.VerdictUnknown || len(vulns.asked) != 1 {
		t.Errorf("finding Dependency-Track does not report: %s, asked %v", v, vulns.asked)
	}
	if v, _, _ := (&Adapter{}).Verdict(ctx, f, refs, "2.17.1"); v != store.VerdictUnknown {
		t.Errorf("without the API: %s", v)
	}
}

type fakeAnalyses struct{ got []AnalysisUpdate }

func (f *fakeAnalyses) SetAnalysis(_ context.Context, a AnalysisUpdate) error {
	f.got = append(f.got, a)
	return nil
}

func TestWriteDecision(t *testing.T) {
	ref := finding.Ref{Source: Name, Project: "p", Component: "c", Vuln: "v"}
	a := &Adapter{}
	if !a.Keeps(ref) || a.Ready() {
		t.Fatalf("keeps=%v ready=%v", a.Keeps(ref), a.Ready())
	}
	if a.Keeps(finding.Ref{Source: Name, Project: "p"}) || a.Keeps(finding.Ref{Source: "patchline", Project: "p", Component: "c", Vuln: "v"}) {
		t.Error("keeps an incomplete or foreign ref")
	}
	if err := a.WriteDecision(context.Background(), ref, source.Decision{Kind: store.RequestFalsePositive}); err == nil {
		t.Error("wrote without the API")
	}

	w := &fakeAnalyses{}
	a.Analyses = w
	err := a.WriteDecision(context.Background(), ref, source.Decision{RequestID: 4, Kind: store.RequestNotAffected,
		Justification: "code_not_reachable", Reason: "only\n in tests", RequestedBy: "Dev", ApprovedBy: "Lead"})
	if err != nil || len(w.got) != 1 {
		t.Fatalf("err=%v got=%+v", err, w.got)
	}
	got := w.got[0]
	if got.ProjectUUID != "p" || got.ComponentUUID != "c" || got.VulnerabilityUUID != "v" || got.State != "NOT_AFFECTED" ||
		got.Justification != "CODE_NOT_REACHABLE" || got.Details != "only in tests" ||
		got.Comment != "Not affected (code_not_reachable) in Patchline (request #4): requested by Dev, approved by Lead. only in tests" {
		t.Errorf("analysis = %+v", got)
	}
}

func TestLink(t *testing.T) {
	ref := finding.Ref{Source: Name, Project: "p"}
	if _, url := (&Adapter{}).Link(ref); url != "" {
		t.Errorf("link without UIURL: %q", url)
	}
	label, url := (&Adapter{UIURL: "http://dt.local/"}).Link(ref)
	if label != "Dependency-Track" || url != "http://dt.local/projects/p/findings" {
		t.Errorf("link = %q %q", label, url)
	}
}
