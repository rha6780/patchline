package store

import (
	"context"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
)

func TestKEVStorage(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.ReplaceKEV(ctx, []KEVEntry{{CVEID: "CVE-2021-44228"}, {CVEID: "CVE-2017-5638"}}, "v1"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceKEV(ctx, []KEVEntry{{CVEID: "CVE-2021-44228"}}, "v2"); err != nil {
		t.Fatal(err)
	}
	set, err := s.KEVSet(ctx)
	if err != nil || len(set) != 1 || !set["CVE-2021-44228"] {
		t.Fatalf("set = %v err %v", set, err)
	}
	if v, _ := s.Setting(ctx, "kev.version"); v != "v2" {
		t.Errorf("version = %q", v)
	}
	if v, _ := s.Setting(ctx, "kev.refreshed_at"); v == "" {
		t.Error("refreshed_at not set")
	}
	if v, err := s.Setting(ctx, "missing"); v != "" || err != nil {
		t.Errorf("missing setting = %q %v", v, err)
	}
}

func TestSLAUpdatesAndReminders(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	epss := 0.9
	id, _, _ := s.UpsertFinding(ctx, finding.Observation{Service: "svc", Environment: "main", ComponentRef: "x",
		VulnID: "CVE-1", Severity: finding.SeverityMedium, EPSS: &epss}, nil)

	open, err := s.OpenFindingsForSLA(ctx)
	if err != nil || len(open) != 1 || open[0].EPSS == nil || *open[0].EPSS != 0.9 || open[0].SLAStartedAt == nil {
		t.Fatalf("open = %+v err %v", open, err)
	}

	due := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	if err := s.UpdateSLA(ctx, SLAUpdate{FindingID: id, EffectiveSeverity: "medium", Due: &due, Silent: true}, open[0].Finding); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordReminder(ctx, id, ReminderDueSoon, formatTime(due), time.Now()); err != nil {
		t.Fatal(err)
	}
	open, _ = s.OpenFindingsForSLA(ctx)
	if open[0].RemindedDueSoonAt == nil || open[0].DueAt == nil {
		t.Fatalf("after reminder: %+v", open[0])
	}

	// Escalation moves the due date: reminders reset, event recorded.
	earlier := due.AddDate(0, 0, -20)
	if err := s.UpdateSLA(ctx, SLAUpdate{FindingID: id, KEV: true, EffectiveSeverity: "critical", Reasons: []string{"in CISA KEV"}, Due: &earlier}, open[0].Finding); err != nil {
		t.Fatal(err)
	}
	open, _ = s.OpenFindingsForSLA(ctx)
	f := open[0]
	if f.RemindedDueSoonAt != nil || !f.KEV || f.EffectiveSeverity != "critical" || f.DisplaySeverity() != "critical" || len(f.SLAReasons) != 1 {
		t.Fatalf("after escalation: %+v", f)
	}
	if !f.Overdue("2026-12-01T00:00:00.000Z") || f.Overdue("2026-10-01T00:00:00.000Z") {
		t.Error("overdue check")
	}

	events, _ := s.FindingEvents(ctx, id)
	kinds := []string{}
	for _, e := range events {
		kinds = append(kinds, e.Kind)
	}
	if len(kinds) != 3 || kinds[1] != finding.EventReminder || kinds[2] != finding.EventSLAChanged {
		t.Fatalf("events = %v (first verdict is silent)", kinds)
	}

	overdue, _ := s.ListFindings(ctx, FindingFilter{DueBefore: "2026-12-01T00:00:00.000Z"})
	if len(overdue) != 1 {
		t.Errorf("due-before filter = %d", len(overdue))
	}
}
