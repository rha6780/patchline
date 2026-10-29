package notify

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/i18n"
	"github.com/rha6780/patchline/internal/store"
)

// SeverityEmoji returns a colored marker for a severity.
func SeverityEmoji(sev string) string {
	switch sev {
	case finding.SeverityCritical:
		return "🔴"
	case finding.SeverityHigh:
		return "🟠"
	case finding.SeverityMedium:
		return "🟡"
	case finding.SeverityLow:
		return "🔵"
	}
	return "⚪"
}

// StateLabel returns a short human label for a state.
func StateLabel(l i18n.Lang, s string) string {
	key := "state." + s
	if !i18n.Has(key) {
		return s
	}
	return l.T(key)
}

// VerdictLabel describes a fix verdict.
func VerdictLabel(l i18n.Lang, v string) string {
	switch v {
	case store.VerdictFixes, store.VerdictInsufficient:
		return l.T("verdict." + v)
	}
	return l.T("verdict.unknown")
}

// Component returns name@version.
func Component(f store.Finding) string {
	name := f.ComponentName
	if name == "" {
		name = f.ComponentRef
	}
	if f.ComponentVersion != "" {
		return name + "@" + f.ComponentVersion
	}
	return name
}

// PRRef renders "owner/repo#12".
func PRRef(repo string, number int) string {
	return fmt.Sprintf("%s#%d", repo, number)
}

// DueText describes a due date relative to now: "due 2026-11-05 (in 6
// days)" or "overdue by 2 days (due 2026-11-05)".
func DueText(l i18n.Lang, due string, now time.Time) string {
	t, err := time.Parse(store.TimeLayout, due)
	if err != nil {
		return due
	}
	day := t.UTC().Format("2006-01-02")
	d := t.Sub(now)
	switch {
	case d < 0:
		return l.T("due.overdue", Days(l, -d), day)
	case d < 24*time.Hour:
		return l.T("due.today", day)
	default:
		return l.T("due.in", day, Days(l, d))
	}
}

// Days renders a duration as hours (under a day) or rounded days.
func Days(l i18n.Lang, d time.Duration) string {
	if d < 24*time.Hour {
		return l.T("dur.hours", int(d.Hours()))
	}
	n := int(math.Round(d.Hours() / 24))
	if n == 1 {
		return l.T("dur.day")
	}
	return l.T("dur.days", n)
}

// Reason translates a stored escalation reason ("in CISA KEV",
// "EPSS 0.94", "internet exposure").
func Reason(l i18n.Lang, r string) string {
	switch {
	case r == "in CISA KEV":
		return l.T("reason.kev")
	case strings.HasSuffix(r, " exposure"):
		return l.T("reason.exposure", strings.TrimSuffix(r, " exposure"))
	}
	return r
}

// SeverityText is the effective severity, with the scanner's when they
// differ: "critical (scanner: high, in CISA KEV)".
func SeverityText(l i18n.Lang, f store.Finding) string {
	sev := f.DisplaySeverity()
	if sev == f.Severity && len(f.SLAReasons) == 0 {
		return sev
	}
	var parts []string
	if sev != f.Severity {
		parts = append(parts, l.T("sev.scanner", f.Severity))
	}
	for _, r := range f.SLAReasons {
		parts = append(parts, Reason(l, r))
	}
	return sev + " (" + strings.Join(parts, ", ") + ")"
}

// Summary is a one-line plain-text description, used as the message
// fallback text and by the console sink.
func Summary(m Message) string {
	f := m.Finding
	return m.Lang.T("summary", strings.ToUpper(f.DisplaySeverity()), f.VulnID, Component(f),
		f.Service, f.Environment, StateLabel(m.Lang, f.State))
}

// EventText describes an event for a thread reply. Events that are already
// part of the message (detection, the notification itself) return "".
func EventText(l i18n.Lang, e store.FindingEvent) string {
	var ev map[string]any
	_ = json.Unmarshal(e.Evidence, &ev)
	str := func(k string) string {
		if v, ok := ev[k].(string); ok {
			return v
		}
		return ""
	}

	switch e.Kind {
	case finding.EventStateChanged:
		text := stateChange(l, e)
		switch str("reason") {
		case store.ReasonAbsentFromSnapshot:
			snap, _ := ev["snapshot"].(map[string]any)
			return text + l.T("ev.absent") + commitSuffix(l, snap)
		case store.ReasonSeenAgain:
			obs, _ := ev["observation"].(map[string]any)
			return text + l.T("ev.seen_again") + commitSuffix(l, obs)
		case store.ReasonApproved:
			return text + l.T("ev.approved_by", str("by_name"))
		}
		if a := str("analysis_state"); a != "" {
			text += l.T("ev.analysis", a)
			if s, _ := ev["suppressed"].(bool); s {
				text += l.T("ev.suppressed")
			}
			text += ")"
		}
		return text
	case finding.EventSeverityChanged:
		return l.T("ev.severity", str("from"), str("to"))
	case finding.EventPRLinked, finding.EventPRUpdated, finding.EventPRMerged, finding.EventPRClosed:
		return prText(l, e, ev)
	case finding.EventSLAChanged:
		return slaText(l, ev)
	case finding.EventReminder:
		if str("kind") == store.ReminderOverdue {
			return l.T("rem.overdue", dateOnly(str("due")))
		}
		return l.T("rem.soon", dateOnly(str("due")))
	case finding.EventAssigned:
		if to := str("to"); to != "" {
			return l.T("ev.assigned", to, str("by_name"))
		}
		return l.T("ev.unassigned", str("by_name"))
	case finding.EventExceptionAsked:
		text := l.T("req.asked.risk_acceptance", str("by_name"))
		if str("kind") == store.RequestDueExtension {
			text = l.T("req.asked.due_extension", str("by_name"), dateOnly(str("requested_due")))
		}
		if r := str("reason"); r != "" {
			text += "\n> " + r
		}
		return text
	case finding.EventExceptionDone:
		text := l.T("req."+str("status"), RequestKindLabel(l, str("kind")), str("by_name"))
		if n := str("note"); n != "" {
			text += "\n> " + n
		}
		return text
	case finding.EventDetected, finding.EventNotified:
		return ""
	}
	return l.T("ev.other", e.Kind)
}

// Describe is EventText for timelines: it also describes detection and
// notification events.
func Describe(l i18n.Lang, e store.FindingEvent) string {
	if t := EventText(l, e); t != "" {
		return t
	}
	switch e.Kind {
	case finding.EventDetected:
		return l.T("ev.detected")
	case finding.EventNotified:
		var ev struct {
			Sink    string `json:"sink"`
			Channel string `json:"channel"`
		}
		_ = json.Unmarshal(e.Evidence, &ev)
		if ev.Sink != "" {
			return strings.TrimSpace(l.T("ev.notified", ev.Sink, ev.Channel))
		}
		return l.T("ev.notified_plain")
	}
	return e.Kind
}

func stateChange(l i18n.Lang, e store.FindingEvent) string {
	from, to := "", ""
	if e.FromState != nil {
		from = StateLabel(l, *e.FromState)
	}
	if e.ToState != nil {
		to = StateLabel(l, *e.ToState)
	}
	return l.T("ev.state", from, to)
}

// commitSuffix renders " (commit `abc` on `ref`)" from evidence, or "".
func commitSuffix(l i18n.Lang, m map[string]any) string {
	c, _ := m["commit"].(string)
	if c == "" {
		return ""
	}
	out := l.T("ev.commit", shortSHA(c))
	if r, _ := m["ref"].(string); r != "" {
		out += l.T("ev.on_ref", r)
	}
	return out + ")"
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func prText(l i18n.Lang, e store.FindingEvent, ev map[string]any) string {
	str := func(k string) string { v, _ := ev[k].(string); return v }
	num := 0
	if f, ok := ev["number"].(float64); ok {
		num = int(f)
	}
	ref := PRRef(str("repository"), num)
	if u := str("url"); u != "" {
		ref += " " + u
	}

	var text string
	switch e.Kind {
	case finding.EventPRLinked, finding.EventPRUpdated:
		key := "pr.opened"
		if e.Kind == finding.EventPRUpdated {
			key = "pr.updated"
		}
		change := str("to_version")
		if from := str("from_version"); from != "" {
			change = from + " → " + change
		}
		text = l.T(key, ref, str("package"), change, VerdictLabel(l, str("verdict")))
		if d := str("verdict_detail"); d != "" && str("verdict") != store.VerdictUnknown {
			text += " (" + d + ")"
		}
	case finding.EventPRMerged:
		text = l.T("pr.merged", ref)
		if sha := str("merge_sha"); sha != "" {
			text += l.T("pr.merge_commit", shortSHA(sha))
		}
		text += l.T("pr.wait")
	case finding.EventPRClosed:
		text = l.T("pr.closed", ref)
	}
	if e.FromState != nil && e.ToState != nil {
		text += "\n" + stateChange(l, e)
	}
	return text
}

func slaText(l i18n.Lang, ev map[string]any) string {
	str := func(k string) string { v, _ := ev[k].(string); return v }
	from, to := str("from_severity"), str("to_severity")
	var reasons []string
	if rs, ok := ev["reasons"].([]any); ok {
		for _, r := range rs {
			if s, ok := r.(string); ok {
				reasons = append(reasons, Reason(l, s))
			}
		}
	}
	var text string
	switch {
	case from != to && finding.SeverityRank(to) < finding.SeverityRank(from):
		text = l.T("sla.escalated", from, to)
	case from != to:
		text = l.T("sla.lowered", from, to)
	default:
		text = l.T("sla.due_updated")
	}
	if len(reasons) > 0 {
		text += " (" + strings.Join(reasons, ", ") + ")"
	}
	if _, ok := ev["extension"]; ok {
		text = l.T("sla.extended", str("by_name"))
	}
	if d := str("to_due"); d != "" {
		text += l.T("sla.due", dateOnly(d))
		if f := str("from_due"); f != "" && f != d {
			text += l.T("sla.was", dateOnly(f))
		}
	} else if str("from_due") != "" {
		text += l.T("sla.no_due")
	}
	return text
}

// RequestKindLabel names a request kind (risk acceptance, due extension).
func RequestKindLabel(l i18n.Lang, kind string) string {
	key := "req.kind." + kind
	if !i18n.Has(key) {
		return kind
	}
	return l.T(key)
}

// RequestStatusLabel names a request status.
func RequestStatusLabel(l i18n.Lang, status string) string {
	key := "req.status." + status
	if !i18n.Has(key) {
		return status
	}
	return l.T(key)
}

func dateOnly(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}
