// Package notify keeps one chat message per finding up to date.
//
// For each finding with events not yet reflected in a sink, the Notifier
// posts a message (first time), or updates the message and adds the new
// events to its thread. Progress is stored per sink, so a crash or a sink
// outage only delays messages.
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/store"
)

// Ref identifies a posted message.
type Ref struct {
	Channel string
	ID      string
}

// Message is what a sink renders for one finding.
type Message struct {
	Finding store.Finding
	// Service is nil for findings whose project is not in the inventory.
	Service *inventory.Service
	// Link points to the finding in Dependency-Track, when known.
	Link string
	// PullRequests are the pull requests linked to the finding.
	PullRequests []store.PullRequestLink
}

// Sink delivers messages to a chat system.
type Sink interface {
	Name() string
	// Post creates the message in channel and returns where it landed.
	Post(ctx context.Context, channel string, m Message) (Ref, error)
	// Update replaces the message content.
	Update(ctx context.Context, ref Ref, m Message) error
	// Reply adds a line to the message's thread.
	Reply(ctx context.Context, ref Ref, text string) error
	// NeedsChannel reports whether Post requires a channel.
	NeedsChannel() bool
}

// RateLimitError asks the notifier to pause before the next call.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited, retry after %s", e.RetryAfter)
}

// Store is the persistence the notifier needs.
type Store interface {
	PendingNotifications(ctx context.Context, sink, minSeverity string, limit int) ([]store.NotificationWork, error)
	RecordNotification(ctx context.Context, r store.NotificationResult) error
	MarkNotificationFailed(ctx context.Context, findingID int64, sink string, cause error, retryAfter time.Duration) error
	FindingPullRequests(ctx context.Context, findingID int64) ([]store.PullRequestLink, error)
}

// Notifier drives a sink.
type Notifier struct {
	Store     Store
	Sink      Sink
	Inventory *inventory.Inventory
	Logger    *slog.Logger

	// DefaultChannel is used for findings whose service has no
	// slack_channel, including unregistered projects.
	DefaultChannel string
	// MinSeverity is the lowest severity that is posted (default medium).
	MinSeverity string
	// DTUIURL, when set, adds a Dependency-Track link to messages.
	DTUIURL string

	PollInterval time.Duration // default 10s
	BatchSize    int           // default 20

	once sync.Once
	wake chan struct{}
}

func (n *Notifier) init() {
	n.once.Do(func() {
		if n.Logger == nil {
			n.Logger = slog.Default()
		}
		if n.Inventory == nil {
			n.Inventory = inventory.Empty()
		}
		if n.MinSeverity == "" {
			n.MinSeverity = finding.SeverityMedium
		}
		if n.PollInterval == 0 {
			n.PollInterval = 10 * time.Second
		}
		if n.BatchSize == 0 {
			n.BatchSize = 20
		}
		n.wake = make(chan struct{}, 1)
	})
}

// Wake asks the notifier to run now. It never blocks.
func (n *Notifier) Wake() {
	n.init()
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// Run delivers notifications until ctx is cancelled.
func (n *Notifier) Run(ctx context.Context) {
	n.init()
	ticker := time.NewTicker(n.PollInterval)
	defer ticker.Stop()
	for {
		pause, err := n.RunOnce(ctx)
		if err != nil && ctx.Err() == nil {
			n.Logger.Error("notification run failed", "sink", n.Sink.Name(), "err", err)
		}
		if pause > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(pause):
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-n.wake:
		}
	}
}

// RunOnce handles one batch of pending work. It returns a pause when the
// sink asked to slow down.
func (n *Notifier) RunOnce(ctx context.Context) (pause time.Duration, err error) {
	n.init()
	work, err := n.Store.PendingNotifications(ctx, n.Sink.Name(), n.MinSeverity, n.BatchSize)
	if err != nil {
		return 0, err
	}
	for _, w := range work {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := n.deliver(ctx, w); err != nil {
			var rl *RateLimitError
			retry := backoff(w.Attempts + 1)
			if errors.As(err, &rl) {
				retry = rl.RetryAfter
			}
			n.Logger.Warn("notification failed", "sink", n.Sink.Name(), "finding", w.Finding.ID,
				"attempt", w.Attempts+1, "retry_in", retry, "err", err)
			if mErr := n.Store.MarkNotificationFailed(ctx, w.Finding.ID, n.Sink.Name(), err, retry); mErr != nil {
				return 0, mErr
			}
			if rl != nil {
				return rl.RetryAfter, nil
			}
		}
	}
	return 0, nil
}

func (n *Notifier) deliver(ctx context.Context, w store.NotificationWork) error {
	if len(w.NewEvents) == 0 {
		return nil
	}
	last := w.NewEvents[len(w.NewEvents)-1].ID
	msg := n.message(w.Finding)
	prs, err := n.Store.FindingPullRequests(ctx, w.Finding.ID)
	if err != nil {
		return err
	}
	msg.PullRequests = prs
	result := store.NotificationResult{FindingID: w.Finding.ID, Sink: n.Sink.Name(), Channel: w.Channel, MessageRef: w.MessageRef, LastEventID: last}

	if w.MessageRef == "" {
		channel := n.channelFor(msg)
		switch {
		case !finding.State(w.Finding.State).Open():
			// Closed before anyone was told: nothing to act on.
			return n.Store.RecordNotification(ctx, result)
		case channel == "" && n.Sink.NeedsChannel():
			n.Logger.Warn("no channel for finding; set slack_channel in the inventory or PATCHLINE_SLACK_DEFAULT_CHANNEL",
				"finding", w.Finding.ID, "service", w.Finding.Service)
			return n.Store.RecordNotification(ctx, result)
		}
		ref, err := n.Sink.Post(ctx, channel, msg)
		if err != nil {
			return err
		}
		result.Channel, result.MessageRef, result.Posted = ref.Channel, ref.ID, true
		n.Logger.Info("finding notified", "sink", n.Sink.Name(), "finding", w.Finding.ID, "channel", ref.Channel)
		return n.Store.RecordNotification(ctx, result)
	}

	ref := Ref{Channel: w.Channel, ID: w.MessageRef}
	if err := n.Sink.Update(ctx, ref, msg); err != nil {
		return err
	}
	for i, e := range w.NewEvents {
		text := EventText(e)
		if text == "" {
			continue
		}
		if err := n.Sink.Reply(ctx, ref, text); err != nil {
			// Keep the replies that went out.
			if i > 0 {
				result.LastEventID = w.NewEvents[i-1].ID
				if rErr := n.Store.RecordNotification(ctx, result); rErr != nil {
					return rErr
				}
			}
			return err
		}
	}
	return n.Store.RecordNotification(ctx, result)
}

func (n *Notifier) message(f store.Finding) Message {
	m := Message{Finding: f}
	if f.Registered {
		if s, ok := n.Inventory.Service(f.Service); ok {
			m.Service = s
		}
	}
	if n.DTUIURL != "" && f.DTProjectUUID != "" {
		m.Link = trimSlash(n.DTUIURL) + "/projects/" + f.DTProjectUUID + "/findings"
	}
	return m
}

func (n *Notifier) channelFor(m Message) string {
	if m.Service != nil && m.Service.SlackChannel != "" {
		return m.Service.SlackChannel
	}
	return n.DefaultChannel
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// backoff returns 30s, 1m, 2m, ... capped at 1h.
func backoff(attempt int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempt && d < time.Hour; i++ {
		d *= 2
	}
	return min(d, time.Hour)
}
