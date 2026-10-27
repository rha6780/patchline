package notify

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rha6780/patchline/internal/finding"
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
func StateLabel(s string) string {
	switch finding.State(s) {
	case finding.StateNeedsReview:
		return "❓ Needs review"
	case finding.StateNew:
		return "🆕 New"
	case finding.StateInProgress:
		return "🛠️ In progress"
	case finding.StateAwaitingVerification:
		return "⏳ Awaiting verification"
	case finding.StateResolved:
		return "✅ Resolved"
	case finding.StateNotAffected:
		return "⚪ Not affected"
	case finding.StateRiskAccepted:
		return "⚠️ Risk accepted"
	case finding.StateReopened:
		return "🔁 Reopened"
	}
	return s
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

// Summary is a one-line plain-text description, used as the message
// fallback text and by the console sink.
func Summary(m Message) string {
	f := m.Finding
	return fmt.Sprintf("[%s] %s in %s (%s/%s) — %s",
		strings.ToUpper(f.Severity), f.VulnID, Component(f), f.Service, f.Environment, StateLabel(f.State))
}

// EventText describes an event for a thread reply. Events that are already
// part of the message (detection, the notification itself) return "".
func EventText(e store.FindingEvent) string {
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
		from, to := "", ""
		if e.FromState != nil {
			from = StateLabel(*e.FromState)
		}
		if e.ToState != nil {
			to = StateLabel(*e.ToState)
		}
		text := fmt.Sprintf("State: %s → %s", from, to)
		switch str("reason") {
		case "absent_from_latest_bom":
			snap, _ := ev["snapshot"].(map[string]any)
			return text + " — no longer reported for the latest BOM" + commitSuffix(snap)
		case "seen_again":
			obs, _ := ev["observation"].(map[string]any)
			return text + " — reported again after it was resolved" + commitSuffix(obs)
		}
		if a := str("analysis_state"); a != "" {
			text += fmt.Sprintf(" (Dependency-Track analysis: %s", a)
			if s, _ := ev["suppressed"].(bool); s {
				text += ", suppressed"
			}
			text += ")"
		}
		return text
	case finding.EventSeverityChanged:
		return fmt.Sprintf("Severity: %s → %s", str("from"), str("to"))
	case finding.EventPRLinked, finding.EventPRUpdated, finding.EventPRMerged, finding.EventPRClosed:
		return prText(e, ev)
	case finding.EventDetected, finding.EventNotified:
		return ""
	}
	return "Event: " + e.Kind
}

// commitSuffix renders " (commit `abc` on `ref`)" from evidence, or "".
func commitSuffix(m map[string]any) string {
	c, _ := m["commit"].(string)
	if c == "" {
		return ""
	}
	out := " (commit `" + shortSHA(c) + "`"
	if r, _ := m["ref"].(string); r != "" {
		out += " on `" + r + "`"
	}
	return out + ")"
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// VerdictLabel describes a fix verdict.
func VerdictLabel(v string) string {
	switch v {
	case store.VerdictFixes:
		return "✅ leaves the affected range"
	case store.VerdictInsufficient:
		return "⚠️ still affected"
	}
	return "❔ not verified"
}

// PRRef renders "owner/repo#12".
func PRRef(repo string, number int) string {
	return fmt.Sprintf("%s#%d", repo, number)
}

func prText(e store.FindingEvent, ev map[string]any) string {
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
		verb := "Fix PR opened"
		if e.Kind == finding.EventPRUpdated {
			verb = "Fix PR updated"
		}
		change := str("to_version")
		if from := str("from_version"); from != "" {
			change = from + " → " + change
		}
		text = fmt.Sprintf("🔧 %s: %s — %s %s · %s", verb, ref, str("package"), change, VerdictLabel(str("verdict")))
		if d := str("verdict_detail"); d != "" && str("verdict") != store.VerdictUnknown {
			text += " (" + d + ")"
		}
	case finding.EventPRMerged:
		text = "🔀 Fix PR merged: " + ref
		if sha := str("merge_sha"); sha != "" {
			text += " (commit `" + shortSHA(sha) + "`)"
		}
		text += " — waiting for a rescan to confirm"
	case finding.EventPRClosed:
		text = "🚫 Fix PR closed without merging: " + ref
	}
	if e.FromState != nil && e.ToState != nil {
		text += fmt.Sprintf("\nState: %s → %s", StateLabel(*e.FromState), StateLabel(*e.ToState))
	}
	return text
}
