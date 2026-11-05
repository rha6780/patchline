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

// Advisories judges fix pull requests: whether a target version of a
// finding's component leaves the vulnerability's affected ranges.
type Advisories interface {
	Name() string
	// Verdict returns store.VerdictFixes or store.VerdictInsufficient with
	// a detail ("2.17.1 is outside the affected range ..."), or
	// store.VerdictUnknown when this source has no ranges for the
	// vulnerability and package, so the next one is asked.
	Verdict(ctx context.Context, f store.Finding, refs []finding.Ref, to string) (verdict, detail string, err error)
}

// DecisionWriter records approved decisions in a tool that keeps its own
// analysis, so the decision lives where the tool's users look.
type DecisionWriter interface {
	Name() string
	// Keeps reports whether the tool keeps decisions about ref (and so
	// must receive them).
	Keeps(ref finding.Ref) bool
	// Ready reports whether decisions can be written now (the tool's API
	// is configured).
	Ready() bool
	WriteDecision(ctx context.Context, ref finding.Ref, d Decision) error
}

// Decision is an approved exception request that closes a finding.
type Decision struct {
	RequestID int64
	// Kind is store.RequestRiskAcceptance, RequestNotAffected or
	// RequestFalsePositive.
	Kind string
	// Justification is the CycloneDX justification of not_affected.
	Justification string
	Reason        string
	RequestedBy   string
	ApprovedBy    string
}

// Linker links a ref to the tool's UI.
type Linker interface {
	Name() string
	// Link returns the URL of ref in the tool, or "" when there is none.
	Link(ref finding.Ref) (label, url string)
}

// Link is a ref's page in a tool.
type Link struct {
	Source string `json:"source"`
	Label  string `json:"label"`
	URL    string `json:"url"`
}

// Registry holds the adapters in use, by name and port.
type Registry struct {
	receivers  map[string]Receiver
	reporters  map[string]Reporter
	writers    map[string]DecisionWriter
	linkers    map[string]Linker
	advisories []Advisories
}

// NewRegistry registers each adapter under every port it implements.
// Advisories are asked in the order given.
func NewRegistry(adapters ...any) *Registry {
	r := &Registry{receivers: map[string]Receiver{}, reporters: map[string]Reporter{},
		writers: map[string]DecisionWriter{}, linkers: map[string]Linker{}}
	for _, a := range adapters {
		if v, ok := a.(Receiver); ok {
			r.receivers[v.Webhook()] = v
		}
		if v, ok := a.(Reporter); ok {
			r.reporters[v.Name()] = v
		}
		if v, ok := a.(DecisionWriter); ok {
			r.writers[v.Name()] = v
		}
		if v, ok := a.(Linker); ok {
			r.linkers[v.Name()] = v
		}
		if v, ok := a.(Advisories); ok {
			r.advisories = append(r.advisories, v)
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

// Advisories returns the advisory sources, in the order to ask them.
func (r *Registry) Advisories() []Advisories {
	if r == nil {
		return nil
	}
	return r.advisories
}

// DecisionWriter returns the writer of a ref's source.
func (r *Registry) DecisionWriter(name string) (DecisionWriter, bool) {
	if r == nil {
		return nil, false
	}
	v, ok := r.writers[name]
	return v, ok
}

// Links returns the refs' pages in their tools, one per distinct URL.
func (r *Registry) Links(refs []finding.Ref) []Link {
	if r == nil {
		return nil
	}
	var out []Link
	seen := map[string]bool{}
	for _, ref := range refs {
		l, ok := r.linkers[ref.Source]
		if !ok {
			continue
		}
		label, url := l.Link(ref)
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		out = append(out, Link{Source: ref.Source, Label: label, URL: url})
	}
	return out
}
