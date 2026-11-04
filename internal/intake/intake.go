// Package intake turns stored webhook deliveries into findings.
//
// The HTTP handler only validates and stores each delivery (inbox pattern);
// the Processor works through the inbox in the background, so slow source
// APIs or restarts never lose events, and redelivered events are harmless.
package intake

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/source"
	"github.com/rha6780/patchline/internal/store"
)

// Store is the persistence the processor needs.
type Store interface {
	PendingInbox(ctx context.Context, maxAttempts, limit int) ([]store.InboxItem, error)
	MarkInboxDone(ctx context.Context, id int64, note string) error
	MarkInboxFailed(ctx context.Context, id int64, cause error, retryAfter time.Duration) error
	UpsertFinding(ctx context.Context, obs finding.Observation, evidence map[string]any) (int64, bool, error)
	TouchSourceProject(ctx context.Context, p store.SourceProject, bom bool) error
	ApplyStateByRef(ctx context.Context, ref finding.Ref, to finding.State, evidence map[string]any) (int, error)
	InsertInboxAt(ctx context.Context, source, eventType, dedupKey string, payload []byte, notBefore time.Time) (int64, bool, error)
	ResolveMissingIn(ctx context.Context, source, project string, keep []int64, evidence map[string]any) ([]int64, error)
	ReplaceComponents(ctx context.Context, source, project string, components []store.Component) error
	Components(ctx context.Context, source, project string) ([]store.Component, error)
	SourceProjects(ctx context.Context, source string) ([]store.SourceProject, error)
	SetSnapshotBOM(ctx context.Context, source, project, serial string, version int) error
	OpenFindingsInRepository(ctx context.Context, repository string, environments []string) ([]store.Finding, error)
	LinkPullRequest(ctx context.Context, l store.PullRequestLink) (bool, error)
	ClosePullRequest(ctx context.Context, repository string, number int, merged bool, mergeSHA string) ([]int64, error)
}

// DefaultEnvironment is used when a project has no version.
const DefaultEnvironment = finding.DefaultEnvironment

// Processor drains the webhook inbox.
type Processor struct {
	Store     Store
	Inventory *inventory.Inventory
	// Sources are the tools' adapters; their reporters handle the inbox
	// items of their source.
	Sources *source.Registry
	// Vulnerabilities reads affected ranges for fix PR verdicts. Optional.
	Vulnerabilities VulnerabilityFetcher
	// Matcher detects vulnerabilities in SBOMs uploaded to Patchline. Nil
	// stores uploads without matching them.
	Matcher Matcher
	Logger  *slog.Logger
	// OnChange is called after an item created or changed findings
	// (for example to wake the notifier). Optional.
	OnChange func()
	// Now returns the current time (default time.Now).
	Now func() time.Time

	PollInterval time.Duration // default 5s
	MaxAttempts  int           // default 5
	BatchSize    int           // default 50

	once sync.Once
	wake chan struct{}
}

func (p *Processor) init() { p.once.Do(p.defaults) }

func (p *Processor) defaults() {
	if p.PollInterval == 0 {
		p.PollInterval = 5 * time.Second
	}
	if p.MaxAttempts == 0 {
		p.MaxAttempts = 5
	}
	if p.BatchSize == 0 {
		p.BatchSize = 50
	}
	if p.Logger == nil {
		p.Logger = slog.Default()
	}
	if p.Inventory == nil {
		p.Inventory = inventory.Empty()
	}
	if p.OnChange == nil {
		p.OnChange = func() {}
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	p.wake = make(chan struct{}, 1)
}

// Wake asks the processor to run now instead of waiting for the next poll.
// It never blocks and is safe to call from any goroutine.
func (p *Processor) Wake() {
	p.init()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Run processes the inbox until ctx is cancelled.
func (p *Processor) Run(ctx context.Context) {
	p.init()
	ticker := time.NewTicker(p.PollInterval)
	defer ticker.Stop()
	for {
		if _, err := p.ProcessPending(ctx); err != nil && ctx.Err() == nil {
			p.Logger.Error("inbox processing failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-p.wake:
		}
	}
}

// ProcessPending handles every due inbox item once and returns how many it
// handled. Per-item failures are recorded on the item, not returned.
func (p *Processor) ProcessPending(ctx context.Context) (int, error) {
	p.init()
	handled := 0
	for {
		items, err := p.Store.PendingInbox(ctx, p.MaxAttempts, p.BatchSize)
		if err != nil {
			return handled, err
		}
		if len(items) == 0 {
			return handled, nil
		}
		for _, it := range items {
			if err := ctx.Err(); err != nil {
				return handled, err
			}
			note, err := p.handle(ctx, it)
			if err != nil {
				retry := backoff(it.Attempts + 1)
				p.Logger.Warn("inbox item failed", "id", it.ID, "source", it.Source, "event", it.EventType,
					"attempt", it.Attempts+1, "retry_in", retry, "err", err)
				if mErr := p.Store.MarkInboxFailed(ctx, it.ID, err, retry); mErr != nil {
					return handled, mErr
				}
			} else if err := p.Store.MarkInboxDone(ctx, it.ID, note); err != nil {
				return handled, err
			}
			handled++
		}
		if len(items) < p.BatchSize {
			return handled, nil
		}
	}
}

// backoff returns 30s, 1m, 2m, 4m, ... capped at 30m.
func backoff(attempt int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempt && d < 30*time.Minute; i++ {
		d *= 2
	}
	return min(d, 30*time.Minute)
}

var errUnknownSource = errors.New("unknown inbox source")

func (p *Processor) handle(ctx context.Context, it store.InboxItem) (note string, err error) {
	switch it.Source {
	case SourceGitea:
		return p.handleGitea(ctx, it)
	case SourcePatchline:
		return p.handlePatchline(ctx, it)
	}
	if rep, ok := p.Sources.Reporter(it.Source); ok {
		out, err := rep.Handle(ctx, it, source.Env{Resolve: p.lookup, Now: p.Now})
		if err != nil {
			return "", err
		}
		return p.apply(ctx, it, out)
	}
	return "", fmt.Errorf("%w %q", errUnknownSource, it.Source)
}

// apply records what a reporter found, in order: projects, sightings, the
// snapshot's resolutions, state changes, follow-ups.
func (p *Processor) apply(ctx context.Context, it store.InboxItem, out source.Outcome) (string, error) {
	for _, pr := range out.Projects {
		if err := p.Store.TouchSourceProject(ctx, pr.SourceProject, pr.BOM); err != nil {
			return "", err
		}
	}
	ids := make([]int64, 0, len(out.Sightings))
	created := 0
	for _, s := range out.Sightings {
		obs := s.Observation
		id, isNew, err := p.Store.UpsertFinding(ctx, obs, s.Evidence)
		if err != nil {
			return "", fmt.Errorf("upsert %s %s: %w", obs.ComponentRef, obs.VulnID, err)
		}
		ids = append(ids, id)
		if isNew {
			created++
			p.Logger.Info("new finding", "service", obs.Service, "environment", obs.Environment,
				"component", obs.ComponentRef, "vuln", obs.VulnID, "severity", obs.Severity, "registered", obs.Registered)
		}
	}
	var resolved []int64
	if snap := out.Snapshot; snap != nil {
		var err error
		if resolved, err = p.Store.ResolveMissingIn(ctx, snap.Source, snap.Project, ids, snap.Evidence); err != nil {
			return "", err
		}
	}
	changed := 0
	for _, c := range out.StateChanges {
		n, err := p.Store.ApplyStateByRef(ctx, c.Ref, c.To, c.Evidence)
		if err != nil {
			return "", err
		}
		changed += n
	}
	for _, l := range out.Later {
		if _, _, err := p.Store.InsertInboxAt(ctx, it.Source, l.EventType, l.DedupKey, l.Payload, l.At); err != nil {
			return "", err
		}
	}
	if len(out.Sightings) > 0 || out.Snapshot != nil || changed > 0 {
		p.OnChange()
	}
	if len(out.Sightings) > 0 || out.Snapshot != nil || len(out.StateChanges) > 0 {
		p.Logger.Info("inbox item processed", "id", it.ID, "source", it.Source, "event", it.EventType,
			"sightings", len(out.Sightings), "new_findings", created, "resolved", len(resolved), "state_changes", changed)
	}
	if out.Note == "" && len(out.StateChanges) > 0 && changed == 0 {
		return "no matching finding changed", nil
	}
	return out.Note, nil
}
