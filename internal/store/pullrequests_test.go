package store

import (
	"context"
	"testing"

	"github.com/rha6780/patchline/internal/finding"
)

func TestPullRequestLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	mk := func(env, ref string) finding.Observation {
		return finding.Observation{Service: "storefront", Registered: true, Repository: "acme/api", Environment: env,
			ComponentRef: ref, ComponentName: "org.apache.logging.log4j/log4j-core", ComponentVersion: "2.14.1",
			VulnID: "CVE-2021-44228", Severity: finding.SeverityCritical}
	}
	mainID, _, _ := s.UpsertFinding(ctx, mk("main", "pkg:maven/a"), nil)
	_, _, _ = s.UpsertFinding(ctx, mk("prod", "pkg:maven/a"), nil)

	open, err := s.OpenFindingsInRepository(ctx, "acme/api", []string{"main", "default"})
	if err != nil || len(open) != 1 || open[0].ID != mainID {
		t.Fatalf("open = %+v err %v (want only main)", open, err)
	}

	link := PullRequestLink{FindingID: mainID, Repository: "acme/api", Number: 12, URL: "https://git/acme/api/pulls/12",
		Title: "Update log4j", Package: "org.apache.logging.log4j:log4j-core", FromVersion: "2.14.1", ToVersion: "2.17.1",
		Verdict: VerdictFixes, VerdictDetail: "outside >= 2.0-beta9, < 2.15.0", HeadSHA: "aaa"}
	if changed, err := s.LinkPullRequest(ctx, link); err != nil || !changed {
		t.Fatalf("link: %v %v", changed, err)
	}
	if f, _ := s.GetFinding(ctx, mainID); f.State != "in_progress" {
		t.Fatalf("state after PR opened = %s", f.State)
	}

	// Same PR again (e.g. edited): no new event.
	link.HeadSHA = "bbb"
	if changed, _ := s.LinkPullRequest(ctx, link); changed {
		t.Error("unchanged PR should not add an event")
	}
	// New target version: update event, no state change (already in progress).
	link.ToVersion, link.Verdict = "2.15.0", VerdictFixes
	if changed, _ := s.LinkPullRequest(ctx, link); !changed {
		t.Error("changed target should add an event")
	}

	ids, err := s.ClosePullRequest(ctx, "acme/api", 12, true, "3f2a9c1e")
	if err != nil || len(ids) != 1 || ids[0] != mainID {
		t.Fatalf("merge: %v %v", ids, err)
	}
	if f, _ := s.GetFinding(ctx, mainID); f.State != "awaiting_verification" {
		t.Fatalf("state after merge = %s", f.State)
	}
	if ids, _ := s.ClosePullRequest(ctx, "acme/api", 12, true, "3f2a9c1e"); len(ids) != 0 {
		t.Error("closing an already merged PR should do nothing")
	}

	prs, _ := s.FindingPullRequests(ctx, mainID)
	if len(prs) != 1 || prs[0].State != PRStateMerged || prs[0].MergeSHA != "3f2a9c1e" || prs[0].ToVersion != "2.15.0" {
		t.Fatalf("links = %+v", prs)
	}

	events, _ := s.FindingEvents(ctx, mainID)
	var kinds []string
	for _, e := range events {
		kinds = append(kinds, e.Kind)
	}
	want := []string{"detected", "pr_linked", "pr_updated", "pr_merged"}
	if len(kinds) != len(want) {
		t.Fatalf("events = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("events = %v, want %v", kinds, want)
		}
	}
	if *events[1].ToState != "in_progress" || events[2].ToState != nil || *events[3].ToState != "awaiting_verification" {
		t.Errorf("state transitions on events wrong: %+v", events)
	}
}

func TestClosedWithoutMerge(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	id, _, _ := s.UpsertFinding(ctx, finding.Observation{Service: "a", Repository: "acme/a", Environment: "main",
		ComponentRef: "pkg:npm/x@1", VulnID: "CVE-1", Severity: finding.SeverityHigh}, nil)
	_, _ = s.LinkPullRequest(ctx, PullRequestLink{FindingID: id, Repository: "acme/a", Number: 3, URL: "u", ToVersion: "2", Verdict: VerdictUnknown})
	if ids, _ := s.ClosePullRequest(ctx, "acme/a", 3, false, ""); len(ids) != 1 {
		t.Fatal("close should record an event")
	}
	if f, _ := s.GetFinding(ctx, id); f.State != "in_progress" {
		t.Errorf("closing without merge keeps the state, got %s", f.State)
	}
}
