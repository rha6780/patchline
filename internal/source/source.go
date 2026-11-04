// Package source defines the ports through which vulnerability tools plug
// into Patchline, and a registry of the adapters in use. Adapters live in
// the subpackages (dependencytrack, ...) and implement the ports they can;
// the core (intake, server) only talks to these interfaces.
//
// See docs/design/source-ports.md.
package source

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/store"
)

// Receiver accepts a tool's webhook (POST /webhooks/{Webhook()}) and says
// how to store it in the inbox (as an item of source Name()).
type Receiver interface {
	Name() string
	// Webhook is the path segment under /webhooks/.
	Webhook() string
	// Accept checks the request and the body. It returns ErrUnauthorized
	// (wrapped or not) for a bad secret, another error for a body that is
	// not a valid delivery.
	Accept(r *http.Request, body []byte, s Secrets) (eventType, dedupKey string, err error)
}

// Secrets are the webhook secrets in effect (the environment's, or the
// ones rotated in the UI).
type Secrets struct {
	WebhookToken string
}

// ErrUnauthorized rejects a webhook without the right secret.
var ErrUnauthorized = errors.New("invalid or missing webhook token")

// TokenMatches reports whether the request carries want as ?token= or
// "Authorization: Bearer". An empty want accepts every request.
func TokenMatches(r *http.Request, want string) bool {
	if want == "" {
		return true
	}
	got := r.URL.Query().Get("token")
	if auth := r.Header.Get("Authorization"); got == "" && strings.HasPrefix(auth, "Bearer ") {
		got = strings.TrimPrefix(auth, "Bearer ")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// Reporter turns the inbox items of its source into an Outcome, which
// intake applies.
type Reporter interface {
	Name() string
	Handle(ctx context.Context, item store.InboxItem, env Env) (Outcome, error)
}

// Env is what a reporter may use from Patchline.
type Env struct {
	// Resolve maps a tool's project name to the inventory service. An
	// unknown project resolves to itself, unregistered.
	Resolve func(project string) (service, repository string, registered bool)
	Now     func() time.Time
}

// Outcome is what an inbox item changes. Intake applies it in this order:
// touch the projects, record the sightings, resolve what the snapshot no
// longer contains, apply the state changes, schedule the follow-ups.
type Outcome struct {
	Projects  []Project
	Sightings []Sighting
	// Snapshot, when set, says Sightings are everything the project
	// reports now: its other findings are resolved.
	Snapshot     *Snapshot
	StateChanges []StateChange
	Later        []Followup
	// Note is stored on the inbox item ("ignored: ...", "skipped: ...").
	Note string
}

// Project is a source project the item touched. BOM marks a new BOM
// (its commit, ref and serial are in SourceProject).
type Project struct {
	store.SourceProject
	BOM bool
}

// Sighting is an observation with the evidence recorded on the finding.
type Sighting struct {
	Observation finding.Observation
	Evidence    map[string]any
}

// Snapshot names the project whose findings Sightings are, completely.
type Snapshot struct {
	Source, Project string
	Evidence        map[string]any
}

// StateChange moves the findings the tool names Ref (an analysis decided
// in the tool).
type StateChange struct {
	Ref      finding.Ref
	To       finding.State
	Evidence map[string]any
}

// Followup is an inbox item of the same source to handle at At, such as
// a delayed reconciliation.
type Followup struct {
	EventType, DedupKey string
	Payload             []byte
	At                  time.Time
}

// Registry holds the adapters in use, by name and port.
type Registry struct {
	receivers map[string]Receiver
	reporters map[string]Reporter
}

// NewRegistry registers each adapter under every port it implements.
func NewRegistry(adapters ...any) *Registry {
	r := &Registry{receivers: map[string]Receiver{}, reporters: map[string]Reporter{}}
	for _, a := range adapters {
		if v, ok := a.(Receiver); ok {
			r.receivers[v.Webhook()] = v
		}
		if v, ok := a.(Reporter); ok {
			r.reporters[v.Name()] = v
		}
	}
	return r
}

// Receiver returns the receiver of /webhooks/{webhook}.
func (r *Registry) Receiver(name string) (Receiver, bool) {
	if r == nil {
		return nil, false
	}
	v, ok := r.receivers[name]
	return v, ok
}

// Reporter returns the reporter of an inbox source.
func (r *Registry) Reporter(name string) (Reporter, bool) {
	if r == nil {
		return nil, false
	}
	v, ok := r.reporters[name]
	return v, ok
}
