package notify_test

import (
	"testing"

	"github.com/rha6780/patchline/internal/notify"
	"github.com/rha6780/patchline/internal/sink/webhook"
)

func TestDestinations(t *testing.T) {
	_, inv := setup(t)
	slack := &notify.Notifier{Sink: &recorder{needsChannel: true}, Inventory: inv, DefaultChannel: "#security"}
	noDefault := &notify.Notifier{Sink: &recorder{needsChannel: true}, Inventory: inv}
	prodOnly := &notify.Notifier{Sink: webhook.New("https://hooks.example/secret/path?key=s", "", nil), Inventory: inv,
		Route: notify.Route{MinSeverity: "high", Environments: []string{"prod"}}}
	g := notify.Group{slack, noDefault, prodOnly}

	got := g.Destinations("storefront", true, "main")
	want := []notify.Destination{
		{Sink: "test", Channel: "#sf", MinSeverity: "medium"},
		{Sink: "test", Channel: "#sf", MinSeverity: "medium"},
		{Sink: "webhook", MinSeverity: "high", Skipped: notify.SkipRoute},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("registered %d: got %+v, want %+v", i, got[i], want[i])
		}
	}

	// An unregistered project (Patchline itself, for one) goes to the default channel.
	got = g.Destinations("patchline", false, "prod")
	want = []notify.Destination{
		{Sink: "test", Channel: "#security", MinSeverity: "medium"},
		{Sink: "test", MinSeverity: "medium", Skipped: notify.SkipNoChannel},
		{Sink: "webhook", MinSeverity: "high"},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("unregistered %d: got %+v, want %+v", i, got[i], want[i])
		}
	}

	sinks := g.Sinks()
	if sinks[0].DefaultChannel != "#security" || !sinks[0].NeedsChannel {
		t.Errorf("slack summary %+v", sinks[0])
	}
	if s := sinks[2]; s.Target != "https://hooks.example" || !s.Signs || s.Signed || s.Route.MinSeverity != "high" {
		t.Errorf("webhook summary %+v: the target must not carry the URL's path or query", s)
	}
}
