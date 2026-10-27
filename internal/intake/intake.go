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
	"github.com/rha6780/patchline/internal/source/dependencytrack"
	"github.com/rha6780/patchline/internal/store"
)

// SourceDependencyTrack is the inbox source name for Dependency-Track.
const SourceDependencyTrack = "dependencytrack"

// DefaultEnvironment is used when a Dependency-Track project has no version.
const DefaultEnvironment = "default"

// FindingsFetcher reads the current findings of a project.
type FindingsFetcher interface {
	ProjectSightings(ctx context.Context, p dependencytrack.Project) ([]dependencytrack.Sighting, error)
}

// Store is the persistence the processor needs.
type Store interface {
	PendingInbox(ctx context.Context, maxAttempts, limit int) ([]store.InboxItem, error)
	MarkInboxDone(ctx context.Context, id int64, note string) error
	MarkInboxFailed(ctx context.Context, id int64, cause error, retryAfter time.Duration) error
	UpsertFinding(ctx context.Context, obs finding.Observation, evidence map[string]any) (int64, bool, error)
	TouchSourceProject(ctx context.Context, p store.SourceProject, bom bool) error
}

// Processor drains the webhook inbox.
type Processor struct {
	Store     Store
	Inventory *inventory.Inventory
	// DT is optional. Without it, BOM_PROCESSED events are recorded but
	// findings only arrive through NEW_VULNERABILITY / NEW_VULNERABLE_DEPENDENCY.
	DT     FindingsFetcher
	Logger *slog.Logger

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
	case SourceDependencyTrack:
		return p.handleDependencyTrack(ctx, it)
	default:
		return "", fmt.Errorf("%w %q", errUnknownSource, it.Source)
	}
}

func (p *Processor) handleDependencyTrack(ctx context.Context, it store.InboxItem) (string, error) {
	n, err := dependencytrack.ParseNotification(it.Payload)
	if err != nil {
		return "", err
	}

	switch n.Group {
	case dependencytrack.GroupNewVulnerability, dependencytrack.GroupNewVulnerableDependency:
		sightings, err := n.Sightings()
		if err != nil {
			return "", err
		}
		created, err := p.record(ctx, it, n.Group, sightings, false)
		if err != nil {
			return "", err
		}
		p.Logger.Info("dependency-track notification processed", "id", it.ID, "group", n.Group,
			"sightings", len(sightings), "new_findings", created)
		return "", nil

	case dependencytrack.GroupBOMProcessed:
		project, err := n.SubjectProject()
		if err != nil {
			return "", err
		}
		if err := p.touch(ctx, project, true); err != nil {
			return "", err
		}
		if p.DT == nil {
			p.Logger.Warn("BOM_PROCESSED received but PATCHLINE_DT_URL is not set; findings were not fetched",
				"project", project.Name, "version", project.Version)
			return "skipped: Dependency-Track API not configured", nil
		}
		sightings, err := p.DT.ProjectSightings(ctx, project)
		if err != nil {
			return "", err
		}
		created, err := p.record(ctx, it, n.Group, sightings, true)
		if err != nil {
			return "", err
		}
		p.Logger.Info("dependency-track BOM processed", "id", it.ID, "project", project.Name,
			"version", project.Version, "findings", len(sightings), "new_findings", created)
		return "", nil

	default:
		return "ignored: group " + n.Group, nil
	}
}

// record upserts each sighting and returns how many new findings it created.
func (p *Processor) record(ctx context.Context, it store.InboxItem, group string, sightings []dependencytrack.Sighting, touched bool) (int, error) {
	seen := map[string]bool{}
	created := 0
	for _, s := range sightings {
		if !touched && !seen[s.Project.UUID] {
			if err := p.touch(ctx, s.Project, false); err != nil {
				return created, err
			}
			seen[s.Project.UUID] = true
		}
		obs := p.observe(s)
		_, isNew, err := p.Store.UpsertFinding(ctx, obs, map[string]any{
			"source":             SourceDependencyTrack,
			"notification_group": group,
			"inbox_id":           it.ID,
			"dt_project":         s.Project,
			"dt_vuln_id":         s.Vulnerability.VulnID,
		})
		if err != nil {
			return created, fmt.Errorf("upsert %s %s: %w", obs.ComponentRef, obs.VulnID, err)
		}
		if isNew {
			created++
			p.Logger.Info("new finding", "service", obs.Service, "environment", obs.Environment,
				"component", obs.ComponentRef, "vuln", obs.VulnID, "severity", obs.Severity, "registered", obs.Registered)
		}
	}
	return created, nil
}

func (p *Processor) touch(ctx context.Context, project dependencytrack.Project, bom bool) error {
	service, _, registered := p.resolve(project)
	return p.Store.TouchSourceProject(ctx, store.SourceProject{
		Source: SourceDependencyTrack, ProjectID: project.UUID, Name: project.Name,
		Version: project.Version, Service: service, Registered: registered,
	}, bom)
}

func (p *Processor) resolve(project dependencytrack.Project) (service, repo string, registered bool) {
	if m, ok := p.Inventory.LookupProject(project.Name); ok {
		return m.Service.Name, m.Repository, true
	}
	return project.Name, "", false
}

func (p *Processor) observe(s dependencytrack.Sighting) finding.Observation {
	service, repo, registered := p.resolve(s.Project)
	env := s.Project.Version
	if env == "" {
		env = DefaultEnvironment
	}
	id, aliases := finding.CanonicalID(s.Vulnerability.VulnID, s.Vulnerability.Aliases)
	return finding.Observation{
		Service:             service,
		Registered:          registered,
		Repository:          repo,
		Environment:         env,
		ComponentRef:        s.Component.Ref(),
		ComponentName:       s.Component.DisplayName(),
		ComponentVersion:    s.Component.Version,
		VulnID:              id,
		Aliases:             aliases,
		Severity:            finding.NormalizeSeverity(s.Vulnerability.Severity),
		Title:               s.Vulnerability.Title,
		DTProjectUUID:       s.Project.UUID,
		DTComponentUUID:     s.Component.UUID,
		DTVulnerabilityUUID: s.Vulnerability.UUID,
	}
}
