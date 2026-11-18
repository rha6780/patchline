package notify

import "github.com/rha6780/patchline/internal/store"

// Reasons a sink sends nothing for a project.
const (
	// SkipRoute: the sink's services or environments filter leaves it out.
	SkipRoute = "route"
	// SkipNoChannel: Slack, but neither the service's slack_channel nor
	// PATCHLINE_SLACK_DEFAULT_CHANNEL names a channel.
	SkipNoChannel = "no_channel"
)

// Destination is where one sink sends the findings of a project.
type Destination struct {
	Sink string
	// Channel is the Slack channel; empty for sinks without channels.
	Channel string
	// MinSeverity is the lowest effective severity the sink posts.
	MinSeverity string
	// Skipped is SkipRoute or SkipNoChannel when the sink sends nothing.
	Skipped string
}

// Destination says where n sends new findings of a service in an
// environment, by the same rules deliver applies.
func (n *Notifier) Destination(service string, registered bool, environment string) Destination {
	n.init()
	f := store.Finding{Service: service, Registered: registered, Environment: environment}
	d := Destination{Sink: n.Sink.Name(), MinSeverity: n.Route.MinSeverity}
	switch {
	case !n.Route.Matches(f):
		d.Skipped = SkipRoute
	case n.Sink.NeedsChannel():
		if d.Channel = n.channelFor(n.message(f)); d.Channel == "" {
			d.Skipped = SkipNoChannel
		}
	}
	return d
}

// Destinations lists where each sink sends a project's findings.
func (g Group) Destinations(service string, registered bool, environment string) []Destination {
	out := make([]Destination, 0, len(g))
	for _, n := range g {
		out = append(out, n.Destination(service, registered, environment))
	}
	return out
}

// Targeter is implemented by sinks that send to an address worth showing
// (the webhook's host). It must not reveal secrets.
type Targeter interface {
	Target() string
}

// SinkSummary describes a configured sink, for the settings page.
type SinkSummary struct {
	Name string
	// Target is where messages go (a host), when the sink says.
	Target string
	// DefaultChannel is the Slack channel for services without one.
	DefaultChannel string
	NeedsChannel   bool
	// Signs is true for a sink that can sign requests; Signed says
	// whether it does.
	Signs, Signed bool
	Route         Route
}

// Sinks describes the configured sinks.
func (g Group) Sinks() []SinkSummary {
	out := make([]SinkSummary, 0, len(g))
	for _, n := range g {
		n.init()
		s := SinkSummary{Name: n.Sink.Name(), NeedsChannel: n.Sink.NeedsChannel(), Route: n.Route}
		if s.NeedsChannel {
			s.DefaultChannel = n.DefaultChannel
		}
		if t, ok := n.Sink.(Targeter); ok {
			s.Target = t.Target()
		}
		if sg, ok := n.Sink.(interface{ Signed() bool }); ok {
			s.Signs, s.Signed = true, sg.Signed()
		}
		out = append(out, s)
	}
	return out
}
