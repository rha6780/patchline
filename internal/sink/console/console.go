// Package console is a sink that writes notifications to a writer
// (stdout by default). It is used when Slack is not configured, for local
// development and demos.
package console

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/rha6780/patchline/internal/notify"
)

// Sink prints messages.
type Sink struct {
	mu sync.Mutex
	w  io.Writer
}

// New returns a console sink writing to w (stdout when nil).
func New(w io.Writer) *Sink {
	if w == nil {
		w = os.Stdout
	}
	return &Sink{w: w}
}

func (s *Sink) Name() string       { return "console" }
func (s *Sink) NeedsChannel() bool { return false }

func (s *Sink) Post(_ context.Context, channel string, m notify.Message) (notify.Ref, error) {
	if channel == "" {
		channel = "console"
	}
	ref := notify.Ref{Channel: channel, ID: strconv.FormatInt(m.Finding.ID, 10)}
	s.printf("📣 [%s] finding #%s %s\n", channel, ref.ID, notify.Summary(m))
	if m.Service != nil && len(m.Service.Owners) > 0 {
		s.printf("    owners: %v\n", m.Service.Owners)
	}
	if m.Link != "" {
		s.printf("    %s\n", m.Link)
	}
	return ref, nil
}

func (s *Sink) Update(_ context.Context, ref notify.Ref, m notify.Message) error {
	s.printf("✏️  [%s] finding #%s updated: %s\n", ref.Channel, ref.ID, notify.Summary(m))
	return nil
}

func (s *Sink) Reply(_ context.Context, ref notify.Ref, text string) error {
	s.printf("    ↳ [%s] finding #%s: %s\n", ref.Channel, ref.ID, text)
	return nil
}

func (s *Sink) printf(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.w, format, args...)
}
