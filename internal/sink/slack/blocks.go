package slack

import (
	"fmt"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/i18n"
	"github.com/rha6780/patchline/internal/notify"
	"github.com/rha6780/patchline/internal/store"
)

// now is replaceable in tests.
var now = time.Now

// Blocks renders a finding as Block Kit blocks.
func Blocks(m notify.Message) []map[string]any {
	f := m.Finding
	l := m.Lang
	if l == "" {
		l = i18n.Default
	}

	sev := f.DisplaySeverity()
	header := fmt.Sprintf("%s %s · %s", notify.SeverityEmoji(sev), strings.ToUpper(sev), f.VulnID)
	fields := []map[string]any{
		field(l, "blk.service", fmt.Sprintf("%s (%s)", escape(f.Service), escape(f.Environment))),
		field(l, "blk.component", "`"+escape(notify.Component(f))+"`"),
		field(l, "blk.state", notify.StateLabel(l, f.State)),
		field(l, "blk.owners", owners(m)),
	}
	if f.Assignee != "" {
		fields = append(fields, field(l, "blk.assignee", escape(f.Assignee)))
	}
	if len(f.Aliases) > 0 {
		fields = append(fields, field(l, "blk.aliases", escape(strings.Join(f.Aliases, ", "))))
	}
	if f.DueAt != nil && finding.State(f.State).Open() {
		due := notify.DueText(l, *f.DueAt, now())
		if f.Overdue(store.FormatTime(now())) {
			due = "🚨 " + due
		}
		fields = append(fields, field(l, "blk.due", escape(due)))
	}
	if sev != f.Severity || len(f.SLAReasons) > 0 {
		fields = append(fields, field(l, "blk.severity", escape(notify.SeverityText(l, f))))
	}
	if len(m.PullRequests) > 0 {
		var lines []string
		for _, pr := range m.PullRequests {
			lines = append(lines, fmt.Sprintf("<%s|%s> %s · %s", pr.URL, escape(notify.PRRef(pr.Repository, pr.Number)),
				pr.State, notify.VerdictLabel(l, pr.Verdict)))
		}
		fields = append(fields, field(l, "blk.fix_pr", strings.Join(lines, "\n")))
	}

	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": truncate(header, 150), "emoji": true}},
	}
	if f.Title != "" {
		blocks = append(blocks, map[string]any{"type": "section", "text": mrkdwn(escape(truncate(f.Title, 2900)))})
	}
	blocks = append(blocks, map[string]any{"type": "section", "fields": fields})

	var ctx []string
	if f.Repository != "" {
		ctx = append(ctx, l.T("blk.repository")+" `"+escape(f.Repository)+"`")
	}
	if !f.Registered {
		ctx = append(ctx, l.T("blk.unregistered"))
	}
	ctx = append(ctx, l.T("blk.finding", f.ID, escape(f.FirstSeenAt)))
	if m.Link != "" {
		ctx = append(ctx, "<"+m.Link+"|"+l.T("blk.open_dt")+">")
	}
	blocks = append(blocks, map[string]any{
		"type":     "context",
		"elements": []map[string]any{mrkdwn(strings.Join(ctx, " · "))},
	})
	return blocks
}

func owners(m notify.Message) string {
	if m.Service == nil || len(m.Service.Owners) == 0 {
		return "—"
	}
	return escape(strings.Join(m.Service.Owners, ", "))
}

func field(l i18n.Lang, key, value string) map[string]any {
	return mrkdwn("*" + l.T(key) + "*\n" + value)
}

func mrkdwn(text string) map[string]any {
	return map[string]any{"type": "mrkdwn", "text": text}
}

// escape encodes the characters Slack treats as control sequences.
func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
