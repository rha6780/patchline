package slack

import (
	"fmt"
	"strings"

	"github.com/rha6780/patchline/internal/notify"
)

// Blocks renders a finding as Block Kit blocks.
func Blocks(m notify.Message) []map[string]any {
	f := m.Finding

	header := fmt.Sprintf("%s %s · %s", notify.SeverityEmoji(f.Severity), strings.ToUpper(f.Severity), f.VulnID)
	fields := []map[string]any{
		mrkdwn(fmt.Sprintf("*Service*\n%s (%s)", escape(f.Service), escape(f.Environment))),
		mrkdwn(fmt.Sprintf("*Component*\n`%s`", escape(notify.Component(f)))),
		mrkdwn("*State*\n" + notify.StateLabel(f.State)),
		mrkdwn("*Owners*\n" + owners(m)),
	}
	if len(f.Aliases) > 0 {
		fields = append(fields, mrkdwn("*Aliases*\n"+escape(strings.Join(f.Aliases, ", "))))
	}
	if f.DueAt != nil {
		fields = append(fields, mrkdwn("*Due*\n"+escape(*f.DueAt)))
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
		ctx = append(ctx, "Repository `"+escape(f.Repository)+"`")
	}
	if !f.Registered {
		ctx = append(ctx, "⚠️ Project not in inventory")
	}
	ctx = append(ctx, fmt.Sprintf("Finding #%d · first seen %s", f.ID, escape(f.FirstSeenAt)))
	if m.Link != "" {
		ctx = append(ctx, "<"+m.Link+"|Open in Dependency-Track>")
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
