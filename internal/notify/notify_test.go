package notify_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/notify"
	"github.com/rha6780/patchline/internal/sink/console"
	"github.com/rha6780/patchline/internal/store"
)

// recorder is a Sink that records calls and can fail on demand.
type recorder struct {
	needsChannel bool
	calls        []string
	failPost     error
	failReplyAt  int // 1-based reply index to fail, 0 = never
	replies      int
}

func (r *recorder) Name() string       { return "test" }
func (r *recorder) NeedsChannel() bool { return r.needsChannel }
func (r *recorder) Post(_ context.Context, ch string, m notify.Message) (notify.Ref, error) {
	if r.failPost != nil {
		return notify.Ref{}, r.failPost
	}
	r.calls = append(r.calls, "post "+ch+" "+m.Finding.State)
	return notify.Ref{Channel: "C-" + ch, ID: "ts1"}, nil
}
func (r *recorder) Update(_ context.Context, ref notify.Ref, m notify.Message) error {
	r.calls = append(r.calls, "update "+ref.Channel+" "+m.Finding.State)
	return nil
}
func (r *recorder) Reply(_ context.Context, ref notify.Ref, text string) error {
	r.replies++
	if r.failReplyAt == r.replies {
		return errors.New("reply failed")
	}
	r.calls = append(r.calls, "reply "+text)
	return nil
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func setup(t *testing.T) (*store.Store, *inventory.Inventory) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "inv.yaml")
	doc := "services:\n  - name: storefront\n    owners: [alice@example.com]\n    slack_channel: '#sf'\n    repositories: [{repo: acme/storefront-api}]\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return store.New(db), inv
}

func obs(service string, registered bool, ref, sev string) finding.Observation {
	return finding.Observation{Service: service, Registered: registered, Environment: "main", ComponentRef: ref,
		ComponentName: ref, VulnID: "CVE-2024-1", Severity: sev,
		DTProjectUUID: "p-" + service, DTComponentUUID: "c-" + ref, DTVulnerabilityUUID: "v"}
}

func TestPostThenUpdateAndThread(t *testing.T) {
	ctx := context.Background()
	st, inv := setup(t)
	sink := &recorder{needsChannel: true}
	n := &notify.Notifier{Store: st, Sink: sink, Inventory: inv, Logger: quiet}

	_, _, _ = st.UpsertFinding(ctx, obs("storefront", true, "pkg:npm/a@1", finding.SeverityCritical), nil)
	_, _, _ = st.UpsertFinding(ctx, obs("storefront", true, "pkg:npm/low@1", finding.SeverityLow), nil) // below threshold

	if _, err := n.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sink.calls, "|"); got != "post #sf new" {
		t.Fatalf("calls = %q", got)
	}

	// Nothing new: nothing sent.
	sink.calls = nil
	_, _ = n.RunOnce(ctx)
	if len(sink.calls) != 0 {
		t.Fatalf("idle run sent %v", sink.calls)
	}

	// Triage in Dependency-Track: update + thread reply.
	_, _ = st.ApplyState(ctx, store.DTKey{ProjectUUID: "p-storefront", ComponentUUID: "c-pkg:npm/a@1", VulnerabilityUUID: "v"},
		finding.StateInProgress, map[string]any{"analysis_state": "IN_TRIAGE"})
	_, _ = n.RunOnce(ctx)
	want := "update C-#sf in_progress|reply State: 🆕 New → 🛠️ In progress (Dependency-Track analysis: IN_TRIAGE)"
	if got := strings.Join(sink.calls, "|"); got != want {
		t.Fatalf("calls = %q\nwant    %q", got, want)
	}
}

func TestSkips(t *testing.T) {
	ctx := context.Background()
	st, inv := setup(t)
	sink := &recorder{needsChannel: true}
	n := &notify.Notifier{Store: st, Sink: sink, Inventory: inv, Logger: quiet}

	// Unregistered and no default channel: skipped, not retried.
	_, _, _ = st.UpsertFinding(ctx, obs("unknown", false, "pkg:npm/u@1", finding.SeverityHigh), nil)
	// Closed before it was ever posted: skipped.
	_, _, _ = st.UpsertFinding(ctx, obs("storefront", true, "pkg:npm/x@1", finding.SeverityHigh), nil)
	_, _ = st.ApplyState(ctx, store.DTKey{ProjectUUID: "p-storefront", ComponentUUID: "c-pkg:npm/x@1", VulnerabilityUUID: "v"},
		finding.StateNotAffected, nil)

	_, _ = n.RunOnce(ctx)
	_, _ = n.RunOnce(ctx)
	if len(sink.calls) != 0 {
		t.Fatalf("calls = %v, want none", sink.calls)
	}

	// With a default channel, a newly detected unregistered finding goes there.
	n2 := &notify.Notifier{Store: st, Sink: &recorder{needsChannel: true}, Inventory: inv, Logger: quiet, DefaultChannel: "#security"}
	_, _, _ = st.UpsertFinding(ctx, obs("other", false, "pkg:npm/o@1", finding.SeverityHigh), nil)
	_, _ = n2.RunOnce(ctx)
	if got := strings.Join(n2.Sink.(*recorder).calls, "|"); got != "post #security new" {
		t.Fatalf("default channel calls = %q", got)
	}
}

func TestFailuresAndRateLimit(t *testing.T) {
	ctx := context.Background()
	st, inv := setup(t)
	sink := &recorder{needsChannel: true, failPost: &notify.RateLimitError{RetryAfter: 3 * time.Second}}
	n := &notify.Notifier{Store: st, Sink: sink, Inventory: inv, Logger: quiet}
	id, _, _ := st.UpsertFinding(ctx, obs("storefront", true, "pkg:npm/a@1", finding.SeverityHigh), nil)

	pause, err := n.RunOnce(ctx)
	if err != nil || pause != 3*time.Second {
		t.Fatalf("pause = %s err = %v", pause, err)
	}
	if msg, _ := st.NotificationError(ctx, id, "test"); !strings.Contains(msg, "rate limited") {
		t.Errorf("last error = %q", msg)
	}
}

// noDelay retries failed notifications immediately.
type noDelay struct{ *store.Store }

func (s noDelay) MarkNotificationFailed(ctx context.Context, id int64, sink string, cause error, _ time.Duration) error {
	return s.Store.MarkNotificationFailed(ctx, id, sink, cause, 0)
}

func TestPartialThreadFailureKeepsProgress(t *testing.T) {
	ctx := context.Background()
	st, inv := setup(t)
	sink := &recorder{needsChannel: true}
	n := &notify.Notifier{Store: noDelay{st}, Sink: sink, Inventory: inv, Logger: quiet}
	o := obs("storefront", true, "pkg:npm/a@1", finding.SeverityHigh)
	_, _, _ = st.UpsertFinding(ctx, o, nil)
	_, _ = n.RunOnce(ctx)

	key := store.DTKey{ProjectUUID: o.DTProjectUUID, ComponentUUID: o.DTComponentUUID, VulnerabilityUUID: "v"}
	_, _ = st.ApplyState(ctx, key, finding.StateInProgress, nil)
	_, _ = st.ApplyState(ctx, key, finding.StateNotAffected, nil)
	sink.calls, sink.replies, sink.failReplyAt = nil, 0, 2
	_, _ = n.RunOnce(ctx) // first reply succeeds, second fails

	sink.calls, sink.failReplyAt = nil, 0
	_, _ = n.RunOnce(ctx) // retry sends only the missing reply
	want := "update C-#sf not_affected|reply State: 🛠️ In progress → ⚪ Not affected"
	if got := strings.Join(sink.calls, "|"); got != want {
		t.Fatalf("retry calls = %q\nwant          %q", got, want)
	}
}

func TestConsoleSink(t *testing.T) {
	ctx := context.Background()
	st, inv := setup(t)
	var buf bytes.Buffer
	n := &notify.Notifier{Store: st, Sink: console.New(&buf), Inventory: inv, Logger: quiet, DTUIURL: "http://dt.local/"}
	o := obs("storefront", true, "pkg:npm/a@1", finding.SeverityCritical)
	_, _, _ = st.UpsertFinding(ctx, o, nil)
	_, _ = n.RunOnce(ctx)
	_, _ = st.ApplyState(ctx, store.DTKey{ProjectUUID: o.DTProjectUUID, ComponentUUID: o.DTComponentUUID, VulnerabilityUUID: "v"},
		finding.StateInProgress, nil)
	_, _ = n.RunOnce(ctx)

	out := buf.String()
	for _, want := range []string{"[#sf] finding #1 [CRITICAL] CVE-2024-1", "alice@example.com",
		"http://dt.local/projects/p-storefront/findings", "updated", "↳ [#sf] finding #1: State: 🆕 New → 🛠️ In progress"} {
		if !strings.Contains(out, want) {
			t.Errorf("console output missing %q:\n%s", want, out)
		}
	}
}
