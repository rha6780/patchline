package notify

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/i18n"
	"github.com/rha6780/patchline/internal/store"
)

func ptr(s string) *string { return &s }

func TestEventText(t *testing.T) {
	ev := func(m map[string]any) json.RawMessage { b, _ := json.Marshal(m); return b }
	tests := []struct {
		e    store.FindingEvent
		want string
	}{
		{store.FindingEvent{Kind: "state_changed", FromState: ptr("in_progress"), ToState: ptr("resolved"),
			Evidence: ev(map[string]any{"reason": "absent_from_latest_bom",
				"snapshot": map[string]any{"commit": "3f2a9c1e0b7d4a6f8e5c", "ref": "refs/heads/main"}})},
			"State: 🛠️ In progress → ✅ Resolved — no longer reported for the latest BOM (commit `3f2a9c1e0b7d` on `refs/heads/main`)"},
		{store.FindingEvent{Kind: "state_changed", FromState: ptr("new"), ToState: ptr("resolved"),
			Evidence: ev(map[string]any{"reason": "absent_from_latest_bom", "snapshot": map[string]any{}})},
			"State: 🆕 New → ✅ Resolved — no longer reported for the latest BOM"},
		{store.FindingEvent{Kind: "state_changed", FromState: ptr("resolved"), ToState: ptr("reopened"),
			Evidence: ev(map[string]any{"reason": "seen_again"})},
			"State: ✅ Resolved → 🔁 Reopened — reported again after it was resolved"},
		{store.FindingEvent{Kind: "state_changed", FromState: ptr("resolved"), ToState: ptr("reopened"),
			Evidence: ev(map[string]any{"reason": "seen_again", "observation": map[string]any{"commit": "9999999bbbbbbb"}})},
			"State: ✅ Resolved → 🔁 Reopened — reported again after it was resolved (commit `9999999bbbbb`)"},
		{store.FindingEvent{Kind: "state_changed", FromState: ptr("new"), ToState: ptr("risk_accepted"),
			Evidence: ev(map[string]any{"analysis_state": "EXPLOITABLE", "suppressed": true})},
			"State: 🆕 New → ⚠️ Risk accepted (Dependency-Track analysis: EXPLOITABLE, suppressed)"},
		{store.FindingEvent{Kind: "severity_changed", Evidence: ev(map[string]any{"from": "medium", "to": "high"})},
			"Severity: medium → high"},
		{store.FindingEvent{Kind: "detected", Evidence: ev(nil)}, ""},
		{store.FindingEvent{Kind: "sla_changed", Evidence: ev(map[string]any{"from_severity": "high", "to_severity": "critical",
			"reasons": []string{"in CISA KEV"}, "from_due": "2026-11-28T00:00:00.000Z", "to_due": "2026-11-05T00:00:00.000Z"})},
			"⏫ Escalated: high → critical (in CISA KEV) · due 2026-11-05 (was 2026-11-28)"},
		{store.FindingEvent{Kind: "sla_changed", Evidence: ev(map[string]any{"from_severity": "high", "to_severity": "high",
			"from_due": "2026-11-28T00:00:00.000Z", "to_due": "2026-11-30T00:00:00.000Z"})},
			"📅 Due date updated · due 2026-11-30 (was 2026-11-28)"},
		{store.FindingEvent{Kind: "reminder", Evidence: ev(map[string]any{"kind": "due_soon", "due": "2026-11-05T00:00:00.000Z"})},
			"⏰ Due soon — 2026-11-05"},
		{store.FindingEvent{Kind: "reminder", Evidence: ev(map[string]any{"kind": "overdue", "due": "2026-11-05T00:00:00.000Z"})},
			"🚨 Overdue — the SLA ended 2026-11-05"},
		{store.FindingEvent{Kind: "pr_linked", FromState: ptr("new"), ToState: ptr("in_progress"),
			Evidence: ev(map[string]any{"repository": "acme/api", "number": 12, "url": "https://git/pulls/12",
				"package": "log4j-core", "from_version": "2.14.1", "to_version": "2.17.1",
				"verdict": "fixes", "verdict_detail": "2.17.1 is outside the affected range < 2.15.0"})},
			"🔧 Fix PR opened: acme/api#12 https://git/pulls/12 — log4j-core 2.14.1 → 2.17.1 · ✅ leaves the affected range (2.17.1 is outside the affected range < 2.15.0)\nState: 🆕 New → 🛠️ In progress"},
		{store.FindingEvent{Kind: "pr_updated",
			Evidence: ev(map[string]any{"repository": "acme/api", "number": 12, "package": "x", "to_version": "2", "verdict": "unknown", "verdict_detail": "n/a"})},
			"🔧 Fix PR updated: acme/api#12 — x 2 · ❔ not verified"},
		{store.FindingEvent{Kind: "pr_merged", FromState: ptr("in_progress"), ToState: ptr("awaiting_verification"),
			Evidence: ev(map[string]any{"repository": "acme/api", "number": 12, "merge_sha": "3f2a9c1e0b7d4a6f"})},
			"🔀 Fix PR merged: acme/api#12 (commit `3f2a9c1e0b7d`) — waiting for a rescan to confirm\nState: 🛠️ In progress → ⏳ Awaiting verification"},
		{store.FindingEvent{Kind: "pr_closed", Evidence: ev(map[string]any{"repository": "acme/api", "number": 12})},
			"🚫 Fix PR closed without merging: acme/api#12"},
	}
	for _, tc := range tests {
		if got := EventText(i18n.EN, tc.e); got != tc.want {
			t.Errorf("EventText(%s)\n got %q\nwant %q", tc.e.Kind, got, tc.want)
		}
	}
}

func TestDueAndSeverityText(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	for due, want := range map[string]string{
		"2026-11-05T00:00:00.000Z": "due 2026-11-05 (in 6 days)",
		"2026-10-30T05:00:00.000Z": "due 2026-10-30 (today)",
		"2026-10-28T00:00:00.000Z": "overdue by 2 days (due 2026-10-28)",
		"2026-11-28T23:59:00.000Z": "due 2026-11-28 (in 30 days)",
		"2026-10-31T00:00:00.000Z": "due 2026-10-31 (in 1 day)",
	} {
		if got := DueText(i18n.EN, due, now); got != want {
			t.Errorf("DueText(%s) = %q, want %q", due, got, want)
		}
	}
	f := store.Finding{Severity: "high", EffectiveSeverity: "critical", SLAReasons: []string{"in CISA KEV"}}
	if got := SeverityText(i18n.EN, f); got != "critical (scanner: high, in CISA KEV)" {
		t.Errorf("SeverityText = %q", got)
	}
	if got := SeverityText(i18n.EN, store.Finding{Severity: "low"}); got != "low" {
		t.Errorf("plain = %q", got)
	}
}

func TestKorean(t *testing.T) {
	ev := func(m map[string]any) json.RawMessage { b, _ := json.Marshal(m); return b }
	tests := []struct {
		e    store.FindingEvent
		want string
	}{
		{store.FindingEvent{Kind: "state_changed", FromState: ptr("in_progress"), ToState: ptr("resolved"),
			Evidence: ev(map[string]any{"reason": "absent_from_latest_bom",
				"snapshot": map[string]any{"commit": "3f2a9c1e0b7d4a6f8e5c", "ref": "refs/heads/main"}})},
			"상태: 🛠️ 조치중 → ✅ 해결 — 최신 BOM에서 더 이상 보고되지 않음 (커밋 `3f2a9c1e0b7d`, `refs/heads/main`)"},
		{store.FindingEvent{Kind: "sla_changed", Evidence: ev(map[string]any{"from_severity": "high", "to_severity": "critical",
			"reasons": []string{"in CISA KEV", "internet exposure"}, "to_due": "2026-11-05T00:00:00.000Z"})},
			"⏫ 상향: high → critical (CISA KEV 등재, internet 노출) · 기한 2026-11-05"},
		{store.FindingEvent{Kind: "reminder", Evidence: ev(map[string]any{"kind": "overdue", "due": "2026-11-05T00:00:00.000Z"})},
			"🚨 기한 초과 — SLA 종료일 2026-11-05"},
	}
	for _, tc := range tests {
		if got := EventText(i18n.KO, tc.e); got != tc.want {
			t.Errorf("ko %s:\n got %q\nwant %q", tc.e.Kind, got, tc.want)
		}
	}
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	if got := DueText(i18n.KO, "2026-11-05T00:00:00.000Z", now); got != "기한 2026-11-05 (6일 남음)" {
		t.Errorf("due ko = %q", got)
	}
	if got := Describe(i18n.KO, store.FindingEvent{Kind: "notified", Evidence: ev(map[string]any{"sink": "slack", "channel": "C1"})}); got != "slack C1에 알림 전송" {
		t.Errorf("describe ko = %q", got)
	}
	m := Message{Lang: i18n.KO, Finding: store.Finding{Severity: "high", VulnID: "CVE-1", ComponentName: "x", Service: "s", Environment: "main", State: "new"}}
	if got := Summary(m); got != "[HIGH] CVE-1 · x (s/main) — 🆕 신규" {
		t.Errorf("summary ko = %q", got)
	}
}
