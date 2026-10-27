package intake

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/store"
)

type fakeVulnDT struct {
	fakeDT
	detail dependencytrack.VulnerabilityDetail
	asked  string
}

func (f *fakeVulnDT) Vulnerability(_ context.Context, source, id string) (dependencytrack.VulnerabilityDetail, error) {
	f.asked = source + "/" + id
	return f.detail, nil
}

var log4shell = dependencytrack.VulnerabilityDetail{
	VulnID: "GHSA-jfh8-c2jp-5v3q", Source: "GITHUB",
	AffectedComponents: []dependencytrack.AffectedComponent{{
		IdentityType: "PURL", Identity: "pkg:maven/org.apache.logging.log4j/log4j-core",
		VersionType: "RANGE", VersionStartIncluding: "2.0-beta9", VersionEndExcluding: "2.15.0",
	}},
}

func enqueueGitea(t *testing.T, st *store.Store, fixture string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "source", "gitea", "testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.InsertInbox(context.Background(), SourceGitea, "pull_request", fixture, body); err != nil {
		t.Fatal(err)
	}
}

func TestRenovatePullRequestFlow(t *testing.T) {
	ctx := context.Background()
	dt := &fakeVulnDT{detail: log4shell}
	p, st := setup(t, dt)

	enqueue(t, st, "new_vulnerability.json") // storefront-api@main, log4j-core 2.14.1
	drain(t, p)

	enqueueGitea(t, st, "renovate_opened.json")
	drain(t, p)
	list, _ := st.ListFindings(ctx, store.FindingFilter{Service: "storefront"})
	if len(list) != 1 || list[0].State != "in_progress" {
		t.Fatalf("after PR opened: %+v", list)
	}
	if dt.asked != "GITHUB/GHSA-jfh8-c2jp-5v3q" {
		t.Errorf("looked up %q", dt.asked)
	}
	prs, _ := st.FindingPullRequests(ctx, list[0].ID)
	if len(prs) != 1 || prs[0].Verdict != store.VerdictFixes || prs[0].ToVersion != "2.17.1" || prs[0].Number != 12 {
		t.Fatalf("links = %+v", prs)
	}

	enqueueGitea(t, st, "renovate_merged.json")
	drain(t, p)
	list, _ = st.ListFindings(ctx, store.FindingFilter{Service: "storefront"})
	if list[0].State != "awaiting_verification" {
		t.Fatalf("after merge: %s", list[0].State)
	}
	prs, _ = st.FindingPullRequests(ctx, list[0].ID)
	if prs[0].State != store.PRStateMerged || prs[0].MergeSHA == "" {
		t.Fatalf("link after merge = %+v", prs[0])
	}
}

func TestPullRequestWithoutMatchIsIgnored(t *testing.T) {
	ctx := context.Background()
	p, st := setup(t, nil)
	enqueue(t, st, "new_vulnerable_dependency.json") // apache/axis only
	drain(t, p)
	enqueueGitea(t, st, "renovate_opened.json") // log4j-core
	drain(t, p)
	list, _ := st.ListFindings(ctx, store.FindingFilter{})
	for _, f := range list {
		if f.State != "new" {
			t.Errorf("finding %d moved to %s", f.ID, f.State)
		}
	}
}

func TestJudge(t *testing.T) {
	purl := "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	tests := []struct {
		to      string
		detail  dependencytrack.VulnerabilityDetail
		want    string
		snippet string
	}{
		{"2.17.1", log4shell, store.VerdictFixes, "outside the affected range >= 2.0-beta9, < 2.15.0"},
		{"2.14.2", log4shell, store.VerdictInsufficient, "still in the affected range"},
		{"2.17.1", dependencytrack.VulnerabilityDetail{PatchedVersions: "2.15.0"}, store.VerdictFixes, "patched version 2.15.0"},
		{"2.14.9", dependencytrack.VulnerabilityDetail{PatchedVersions: "2.15.0"}, store.VerdictInsufficient, "< patched"},
		{"2.17.1", dependencytrack.VulnerabilityDetail{PatchedVersions: ">= 2.15.0"}, store.VerdictUnknown, "no affected version range"},
		{"2.17.1", dependencytrack.VulnerabilityDetail{AffectedComponents: []dependencytrack.AffectedComponent{{
			IdentityType: "PURL", Identity: "pkg:maven/other/lib", VersionType: "RANGE", VersionEndExcluding: "9"}}},
			store.VerdictUnknown, "no affected version range"},
	}
	for _, tc := range tests {
		got, detail := Judge(purl, tc.to, tc.detail)
		if got != tc.want || !strings.Contains(detail, tc.snippet) {
			t.Errorf("Judge(%s) = %s %q, want %s containing %q", tc.to, got, detail, tc.want, tc.snippet)
		}
	}
}

func TestPurlHelpers(t *testing.T) {
	if got := purlName("pkg:npm/%40types/node@20.1.0"); got != "@types/node" {
		t.Errorf("purlName = %q", got)
	}
	if got := purlName("pkg:maven/org.apache/Log4j@2?type=jar"); got != "org.apache/log4j" {
		t.Errorf("purlName = %q", got)
	}
	if got := purlBase("pkg:deb/debian/openssl@3.0.11?arch=amd64"); got != "pkg:deb/debian/openssl" {
		t.Errorf("purlBase = %q", got)
	}
}
