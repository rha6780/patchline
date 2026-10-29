package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
)

func TestNotificationWorkflow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	clock := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }

	base := finding.Observation{Service: "svc", Environment: "main", ComponentRef: "pkg:npm/a@1", VulnID: "CVE-1",
		Severity: finding.SeverityHigh, DTProjectUUID: "p", DTComponentUUID: "c", DTVulnerabilityUUID: "v"}
	high, _, _ := s.UpsertFinding(ctx, base, nil)
	low := base
	low.ComponentRef, low.Severity = "pkg:npm/b@1", finding.SeverityLow
	lowID, _, _ := s.UpsertFinding(ctx, low, nil)

	// Not evaluated by the policy yet: nothing is pending.
	if work, _ := s.PendingNotifications(ctx, "slack", finding.SeverityMedium, 10); len(work) != 0 {
		t.Fatalf("unevaluated findings should wait, got %+v", work)
	}
	evaluate(t, s, high, finding.SeverityHigh)
	evaluate(t, s, lowID, finding.SeverityLow)

	work, err := s.PendingNotifications(ctx, "slack", finding.SeverityMedium, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(work) != 1 || work[0].Finding.ID != high || work[0].MessageRef != "" || len(work[0].NewEvents) != 1 {
		t.Fatalf("work = %+v (want only the high finding, unposted, one event)", work)
	}

	// Failure delays the next attempt.
	if err := s.MarkNotificationFailed(ctx, high, "slack", errors.New("channel_not_found"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if work, _ := s.PendingNotifications(ctx, "slack", finding.SeverityMedium, 10); len(work) != 0 {
		t.Fatal("failed notification should wait for retry")
	}
	if msg, _ := s.NotificationError(ctx, high, "slack"); msg != "channel_not_found" {
		t.Errorf("last error = %q", msg)
	}
	clock = clock.Add(2 * time.Minute)
	work, _ = s.PendingNotifications(ctx, "slack", finding.SeverityMedium, 10)
	if len(work) != 1 || work[0].Attempts != 1 {
		t.Fatalf("after backoff: %+v", work)
	}

	// Posting records a notified event, which itself does not trigger work.
	lastID := work[0].NewEvents[len(work[0].NewEvents)-1].ID
	if err := s.RecordNotification(ctx, NotificationResult{FindingID: high, Sink: "slack", Channel: "C1", MessageRef: "111.222", LastEventID: lastID, Posted: true}); err != nil {
		t.Fatal(err)
	}
	if work, _ := s.PendingNotifications(ctx, "slack", finding.SeverityMedium, 10); len(work) != 0 {
		t.Fatalf("nothing should be pending after posting, got %+v", work)
	}

	// A state change makes the message stale.
	if _, err := s.ApplyState(ctx, DTKey{"p", "c", "v"}, finding.StateInProgress, nil); err != nil {
		t.Fatal(err)
	}
	work, _ = s.PendingNotifications(ctx, "slack", finding.SeverityMedium, 10)
	if len(work) != 1 || work[0].MessageRef != "111.222" || work[0].Channel != "C1" ||
		len(work[0].NewEvents) != 1 || work[0].NewEvents[0].Kind != finding.EventStateChanged {
		t.Fatalf("after state change: %+v", work)
	}

	// Another sink tracks its own progress.
	if work, _ := s.PendingNotifications(ctx, "console", finding.SeverityLow, 10); len(work) != 2 {
		t.Fatalf("console work = %d, want 2", len(work))
	}

	events, _ := s.FindingEvents(ctx, high)
	kinds := map[string]int{}
	for _, e := range events {
		kinds[e.Kind]++
	}
	if kinds[finding.EventNotified] != 1 {
		t.Errorf("notified events = %d, want 1", kinds[finding.EventNotified])
	}
}

// evaluate stores a silent policy verdict with the given effective severity.
func evaluate(t *testing.T, s *Store, id int64, sev string) {
	t.Helper()
	prev, err := s.GetFinding(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSLA(context.Background(), SLAUpdate{FindingID: id, EffectiveSeverity: sev, Silent: true}, prev); err != nil {
		t.Fatal(err)
	}
}
