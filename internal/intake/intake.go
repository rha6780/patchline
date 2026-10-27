// Package intake turns stored webhook deliveries into findings.
//
// The HTTP handler only validates and stores each delivery (inbox pattern);
// the Processor works through the inbox in the background, so slow source
// APIs or restarts never lose events, and redelivered events are harmless.
package intake

import (
	"context"
	"encoding/json"
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

// EventReconcile is the inbox event type of a scheduled reconciliation: read
// a project's current findings and resolve the ones that disappeared.
const EventReconcile = "patchline.reconcile"

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
	ApplyState(ctx context.Context, key store.DTKey, to finding.State, evidence map[string]any) (int, error)
	InsertInboxAt(ctx context.Context, source, eventType, dedupKey string, payload []byte, notBefore time.Time) (int64, bool, error)
	ResolveMissing(ctx context.Context, dtProjectUUID string, keep []int64, evidence map[string]any) ([]int64, error)
}

// Processor drains the webhook inbox.
type Processor struct {
	Store     Store
	Inventory *inventory.Inventory
	// DT is optional. Without it, BOM_PROCESSED events are recorded but
	// findings only arrive through NEW_VULNERABILITY / NEW_VULNERABLE_DEPENDENCY.
	DT     FindingsFetcher
	Logger *slog.Logger
	// OnChange is called after an item created or changed findings
	// (for example to wake the notifier). Optional.
	OnChange func()

	// ReconcileDelay is how long to wait after BOM_PROCESSED before reading
	// the project's findings, so Dependency-Track can finish analyzing the
	// new components (default 2m).
	ReconcileDelay time.Duration
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
	if p.ReconcileDelay == 0 {
		p.ReconcileDelay = 2 * time.Minute
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
	case SourceDependencyTrack:
		return p.handleDependencyTrack(ctx, it)
	default:
		return "", fmt.Errorf("%w %q", errUnknownSource, it.Source)
	}
}

func (p *Processor) handleDependencyTrack(ctx context.Context, it store.InboxItem) (string, error) {
	if it.EventType == EventReconcile {
		return p.reconcile(ctx, it)
	}
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
		_, created, err := p.record(ctx, it, n.Group, sightings, false, nil)
		if err != nil {
			return "", err
		}
		p.OnChange()
		p.Logger.Info("dependency-track notification processed", "id", it.ID, "group", n.Group,
			"sightings", len(sightings), "new_findings", created)
		return "", nil

	case dependencytrack.GroupBOMProcessed:
		project, err := n.SubjectProject()
		if err != nil {
			return "", err
		}
		bom := n.SubjectBOM()
		if err := p.touch(ctx, project, &bom); err != nil {
			return "", err
		}
		if p.DT == nil {
			p.Logger.Warn("BOM_PROCESSED received but the Dependency-Track API is not configured; findings were not reconciled",
				"project", project.Name, "version", project.Version)
			return "skipped: Dependency-Track API not configured", nil
		}
		payload, err := json.Marshal(reconcileRequest{Project: project, BOM: bom, InboxID: it.ID, NotifiedAt: n.Timestamp})
		if err != nil {
			return "", err
		}
		due := p.Now().Add(p.ReconcileDelay)
		if _, _, err := p.Store.InsertInboxAt(ctx, SourceDependencyTrack, EventReconcile,
			fmt.Sprintf("reconcile:%d", it.ID), payload, due); err != nil {
			return "", err
		}
		p.Logger.Info("dependency-track BOM processed; reconciliation scheduled", "id", it.ID,
			"project", project.Name, "version", project.Version, "commit", bom.Commit, "due", due.Format(time.RFC3339))
		return "", nil

	case dependencytrack.GroupProjectAuditChange:
		return p.handleAuditChange(ctx, it, n)

	default:
		return "ignored: group " + n.Group, nil
	}
}

func (p *Processor) handleAuditChange(ctx context.Context, it store.InboxItem, n dependencytrack.Notification) (string, error) {
	a, err := n.AuditChange()
	if err != nil {
		return "", err
	}
	to, ok := a.Analysis.FindingState()
	if !ok {
		return "ignored: analysis state " + a.Analysis.State, nil
	}
	changed, err := p.Store.ApplyState(ctx, store.DTKey{
		ProjectUUID:       a.Analysis.Project,
		ComponentUUID:     a.Analysis.Component,
		VulnerabilityUUID: a.Analysis.Vulnerability,
	}, to, map[string]any{
		"source":             SourceDependencyTrack,
		"notification_group": n.Group,
		"inbox_id":           it.ID,
		"analysis_state":     a.Analysis.State,
		"suppressed":         a.Analysis.Suppressed,
		"title":              n.Title,
	})
	if err != nil {
		return "", err
	}
	p.Logger.Info("dependency-track audit change processed", "id", it.ID, "analysis", a.Analysis.State,
		"suppressed", a.Analysis.Suppressed, "to", to, "findings_changed", changed)
	if changed == 0 {
		return "no matching finding changed", nil
	}
	p.OnChange()
	return "", nil
}

// record upserts each sighting. It returns the ids of the findings it saw
// and how many were new.
func (p *Processor) record(ctx context.Context, it store.InboxItem, group string, sightings []dependencytrack.Sighting, touched bool, extra map[string]any) (ids []int64, created int, err error) {
	seen := map[string]bool{}
	for _, s := range sightings {
		if !touched && !seen[s.Project.UUID] {
			if err := p.touch(ctx, s.Project, nil); err != nil {
				return ids, created, err
			}
			seen[s.Project.UUID] = true
		}
		obs := p.observe(s)
		evidence := map[string]any{
			"source":             SourceDependencyTrack,
			"notification_group": group,
			"inbox_id":           it.ID,
			"dt_project":         s.Project,
			"dt_vuln_id":         s.Vulnerability.VulnID,
		}
		for k, v := range extra {
			evidence[k] = v
		}
		id, isNew, err := p.Store.UpsertFinding(ctx, obs, evidence)
		if err != nil {
			return ids, created, fmt.Errorf("upsert %s %s: %w", obs.ComponentRef, obs.VulnID, err)
		}
		ids = append(ids, id)
		if isNew {
			created++
			p.Logger.Info("new finding", "service", obs.Service, "environment", obs.Environment,
				"component", obs.ComponentRef, "vuln", obs.VulnID, "severity", obs.Severity, "registered", obs.Registered)
		}
	}
	return ids, created, nil
}

// reconcileRequest is the payload of a scheduled reconciliation.
type reconcileRequest struct {
	Project    dependencytrack.Project `json:"project"`
	BOM        dependencytrack.BOMInfo `json:"bom"`
	InboxID    int64                   `json:"bom_processed_inbox_id"`
	NotifiedAt string                  `json:"notified_at,omitempty"`
}

// reconcile reads the project's current findings, records them, and
// resolves the project's findings that are no longer reported.
func (p *Processor) reconcile(ctx context.Context, it store.InboxItem) (string, error) {
	var req reconcileRequest
	if err := json.Unmarshal(it.Payload, &req); err != nil {
		return "", fmt.Errorf("decode reconcile request: %w", err)
	}
	if p.DT == nil {
		return "skipped: Dependency-Track API not configured", nil
	}
	sightings, err := p.DT.ProjectSightings(ctx, req.Project)
	if err != nil {
		return "", err
	}
	evidence := map[string]any{
		"source":                 SourceDependencyTrack,
		"dt_project":             req.Project,
		"bom_processed_inbox_id": req.InboxID,
		"bom_processed_at":       req.NotifiedAt,
	}
	bomEvidence := map[string]any{}
	if req.BOM.Commit != "" {
		bomEvidence["commit"] = req.BOM.Commit
	}
	if req.BOM.Ref != "" {
		bomEvidence["ref"] = req.BOM.Ref
	}
	if req.BOM.Serial != "" {
		bomEvidence["bom_serial"] = req.BOM.Serial
	}
	for k, v := range bomEvidence {
		evidence[k] = v
	}
	ids, created, err := p.record(ctx, it, dependencytrack.GroupBOMProcessed, sightings, true, bomEvidence)
	if err != nil {
		return "", err
	}
	resolved, err := p.Store.ResolveMissing(ctx, req.Project.UUID, ids, evidence)
	if err != nil {
		return "", err
	}
	p.OnChange()
	p.Logger.Info("dependency-track project reconciled", "id", it.ID, "project", req.Project.Name,
		"version", req.Project.Version, "findings", len(sightings), "new_findings", created,
		"resolved", len(resolved), "commit", req.BOM.Commit)
	return "", nil
}

func (p *Processor) touch(ctx context.Context, project dependencytrack.Project, bom *dependencytrack.BOMInfo) error {
	service, _, registered := p.resolve(project)
	sp := store.SourceProject{
		Source: SourceDependencyTrack, ProjectID: project.UUID, Name: project.Name,
		Version: project.Version, Service: service, Registered: registered,
	}
	if bom != nil {
		sp.Commit, sp.Ref, sp.BOMSerial = bom.Commit, bom.Ref, bom.Serial
	}
	return p.Store.TouchSourceProject(ctx, sp, bom != nil)
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
