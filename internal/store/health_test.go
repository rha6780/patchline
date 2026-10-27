package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
)

func TestHealthQueries(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	_ = s.TouchSourceProject(ctx, SourceProject{Source: "dependencytrack", ProjectID: "p1", Name: "api", Version: "main", Service: "svc", Registered: true, Commit: "abc1234"}, true)
	_ = s.TouchSourceProject(ctx, SourceProject{Source: "dependencytrack", ProjectID: "p2", Name: "stray", Service: "stray"}, false)
	projects, err := s.ListSourceProjects(ctx)
	if err != nil || len(projects) != 2 || projects[0].Name != "stray" || projects[1].Commit != "abc1234" || projects[1].LastBOMAt == "" {
		t.Fatalf("projects = %+v err %v", projects, err)
	}

	id, _, _ := s.InsertInbox(ctx, "dependencytrack", "BOM_PROCESSED", "k", []byte(`{}`))
	_ = s.MarkInboxFailed(ctx, id, errors.New("dt down"), time.Minute)
	inbox, err := s.ListInboxProblems(ctx, 10)
	if err != nil || len(inbox) != 1 || inbox[0].LastError != "dt down" {
		t.Fatalf("inbox problems = %+v err %v", inbox, err)
	}

	fid, _, _ := s.UpsertFinding(ctx, finding.Observation{Service: "svc", Environment: "main", ComponentRef: "x", VulnID: "CVE-1", Severity: "high"}, nil)
	_ = s.MarkNotificationFailed(ctx, fid, "slack", errors.New("channel_not_found"), time.Minute)
	notes, err := s.ListNotificationProblems(ctx, 10)
	if err != nil || len(notes) != 1 || notes[0].LastError != "channel_not_found" {
		t.Fatalf("notification problems = %+v err %v", notes, err)
	}

	open, _ := s.ListFindings(ctx, FindingFilter{Open: true, Severity: "high"})
	if len(open) != 1 {
		t.Fatalf("open high = %d", len(open))
	}
}
