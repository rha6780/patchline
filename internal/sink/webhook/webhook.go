// Package webhook is a sink that POSTs notifications as JSON to a URL, for
// systems without a built-in sink (Teams workflows, ticketing, an internal
// bus). Every delivery is one finding: when it is first posted
// ("finding.opened") and for each later event ("finding.event"), always
// with the finding's current state.
//
// With a secret, each request carries
//
//	X-Patchline-Signature-256: sha256=<hex HMAC-SHA256 of the body>
//
// so the receiver can check it came from Patchline.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/rha6780/patchline/internal/notify"
	"github.com/rha6780/patchline/internal/store"
)

// Schema names the payload format; it changes only with breaking changes.
const Schema = "patchline.notification/v1"

// Delivery types.
const (
	TypeOpened = "finding.opened"
	TypeEvent  = "finding.event"
)

// Payload is the request body.
type Payload struct {
	Schema string `json:"schema"`
	Type   string `json:"type"`
	// Delivery is unique per finding and event, and the same when a
	// delivery is retried, so receivers can drop duplicates.
	Delivery string `json:"delivery"`
	SentAt   string `json:"sent_at"`
	// Text is a one-line description in the notification language.
	Text         string        `json:"text"`
	Finding      Finding       `json:"finding"`
	Event        *Event        `json:"event,omitempty"`
	PullRequests []PullRequest `json:"pull_requests"`
}

// Finding is the finding's current state.
type Finding struct {
	ID int64 `json:"id"`
	// URL is the finding in Patchline (needs PATCHLINE_PUBLIC_URL).
	URL         string   `json:"url,omitempty"`
	VulnID      string   `json:"vuln_id"`
	Aliases     []string `json:"aliases"`
	Title       string   `json:"title,omitempty"`
	Severity    string   `json:"severity"`
	ScannerSev  string   `json:"scanner_severity"`
	SLAReasons  []string `json:"sla_reasons"`
	KEV         bool     `json:"kev"`
	EPSS        *float64 `json:"epss,omitempty"`
	State       string   `json:"state"`
	Service     string   `json:"service"`
	Registered  bool     `json:"registered"`
	Owners      []string `json:"owners"`
	Environment string   `json:"environment"`
	Repository  string   `json:"repository,omitempty"`
	Component   struct {
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		PURL    string `json:"purl,omitempty"`
	} `json:"component"`
	Assignee    string  `json:"assignee,omitempty"`
	DueAt       *string `json:"due_at,omitempty"`
	FirstSeenAt string  `json:"first_seen_at"`
	ResolvedAt  *string `json:"resolved_at,omitempty"`
	// DTURL is the finding's project in Dependency-Track, when known.
	DTURL string `json:"dependency_track_url,omitempty"`
}

// Event is what happened, for "finding.event".
type Event struct {
	ID         int64           `json:"id"`
	Kind       string          `json:"kind"`
	FromState  *string         `json:"from_state,omitempty"`
	ToState    *string         `json:"to_state,omitempty"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
	OccurredAt string          `json:"occurred_at"`
}

// PullRequest is a fix pull request linked to the finding.
type PullRequest struct {
	Repository string `json:"repository"`
	Number     int    `json:"number"`
	URL        string `json:"url"`
	State      string `json:"state"`
	ToVersion  string `json:"to_version"`
	Verdict    string `json:"verdict"`
}

// Sink posts to one URL.
type Sink struct {
	url    string
	secret []byte
	http   *http.Client
	now    func() time.Time
}

// New returns a webhook sink. secret may be empty (requests are unsigned).
func New(url, secret string, httpClient *http.Client) *Sink {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Sink{url: url, secret: []byte(secret), http: httpClient, now: time.Now}
}

func (s *Sink) Name() string       { return "webhook" }
func (s *Sink) NeedsChannel() bool { return false }

// Post sends "finding.opened".
func (s *Sink) Post(ctx context.Context, _ string, m notify.Message) (notify.Ref, error) {
	id := strconv.FormatInt(m.Finding.ID, 10)
	p := s.payload(TypeOpened, id+".opened", notify.Summary(m), m)
	if err := s.send(ctx, p); err != nil {
		return notify.Ref{}, err
	}
	return notify.Ref{Channel: "webhook", ID: id}, nil
}

// Update does nothing: every event delivery carries the current state.
func (s *Sink) Update(context.Context, notify.Ref, notify.Message) error { return nil }

// Reply is not used; the notifier calls ReplyEvent.
func (s *Sink) Reply(context.Context, notify.Ref, string) error { return nil }

// ReplyEvent sends "finding.event".
func (s *Sink) ReplyEvent(ctx context.Context, _ notify.Ref, m notify.Message, e store.FindingEvent, text string) error {
	p := s.payload(TypeEvent, fmt.Sprintf("%d.%d", m.Finding.ID, e.ID), text, m)
	p.Event = &Event{ID: e.ID, Kind: e.Kind, FromState: e.FromState, ToState: e.ToState, OccurredAt: e.OccurredAt}
	if len(e.Evidence) > 0 && json.Valid(e.Evidence) {
		p.Event.Evidence = e.Evidence
	}
	return s.send(ctx, p)
}

func (s *Sink) payload(typ, delivery, text string, m notify.Message) Payload {
	f := m.Finding
	out := Finding{
		ID: f.ID, URL: m.URL, VulnID: f.VulnID, Aliases: nonNil(f.Aliases), Title: f.Title,
		Severity: f.DisplaySeverity(), ScannerSev: f.Severity, SLAReasons: nonNil(f.SLAReasons),
		KEV: f.KEV, EPSS: f.EPSS, State: f.State, Service: f.Service, Registered: f.Registered,
		Owners: []string{}, Environment: f.Environment, Repository: f.Repository,
		Assignee: f.Assignee, DueAt: f.DueAt, FirstSeenAt: f.FirstSeenAt, ResolvedAt: f.ResolvedAt,
		DTURL: m.DTLink,
	}
	if m.Service != nil {
		out.Owners = nonNil(m.Service.Owners)
	}
	out.Component.Name, out.Component.Version, out.Component.PURL = f.ComponentName, f.ComponentVersion, f.ComponentRef
	if out.Component.Name == "" {
		out.Component.Name = f.ComponentRef
	}
	prs := []PullRequest{}
	for _, pr := range m.PullRequests {
		prs = append(prs, PullRequest{Repository: pr.Repository, Number: pr.Number, URL: pr.URL,
			State: pr.State, ToVersion: pr.ToVersion, Verdict: pr.Verdict})
	}
	return Payload{Schema: Schema, Type: typ, Delivery: delivery, SentAt: s.now().UTC().Format(time.RFC3339),
		Text: text, Finding: out, PullRequests: prs}
}

func (s *Sink) send(ctx context.Context, p Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Patchline-Webhook")
	req.Header.Set("X-Patchline-Event", p.Type)
	req.Header.Set("X-Patchline-Delivery", p.Delivery)
	if len(s.secret) > 0 {
		req.Header.Set("X-Patchline-Signature-256", Sign(s.secret, body))
	}
	res, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))

	switch {
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusServiceUnavailable:
		retry := 30 * time.Second
		if v, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && v > 0 {
			retry = time.Duration(v) * time.Second
		}
		return &notify.RateLimitError{RetryAfter: retry}
	case res.StatusCode < 200 || res.StatusCode > 299:
		return fmt.Errorf("webhook: HTTP %s", res.Status)
	}
	return nil
}

// Sign returns the X-Patchline-Signature-256 value for body.
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
