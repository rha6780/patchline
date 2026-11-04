package dependencytrack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/source"
	"github.com/rha6780/patchline/internal/store"
)

// Name is the source name: the inbox source, /webhooks/dependency-track and
// the refs' source.
const Name = finding.SourceDependencyTrack

// EventReconcile is the inbox event type of a scheduled reconciliation:
// read a project's current findings and resolve the ones that disappeared.
const EventReconcile = "patchline.reconcile"

// FindingsFetcher reads the current findings of a project. *Client
// implements it.
type FindingsFetcher interface {
	ProjectSightings(ctx context.Context, p Project) ([]Sighting, error)
}

// Adapter connects Dependency-Track: it receives its webhooks and turns
// its notifications into sightings, reconciliations and state changes.
type Adapter struct {
	// Client reads a project's findings after BOM_PROCESSED. Without it,
	// findings only arrive through NEW_VULNERABILITY notifications.
	Client FindingsFetcher
	// ReconcileDelay is how long to wait after BOM_PROCESSED before reading
	// the project's findings, so Dependency-Track can finish analyzing the
	// new components (default 2m).
	ReconcileDelay time.Duration
	Logger         *slog.Logger
}

func (a *Adapter) Name() string { return Name }

// Webhook is the path: POST /webhooks/dependency-track.
func (a *Adapter) Webhook() string { return "dependency-track" }

func (a *Adapter) logger() *slog.Logger {
	if a.Logger == nil {
		return slog.Default()
	}
	return a.Logger
}

// Accept checks the webhook token and that the body is a notification.
// The event type is the notification group; the body's hash de-duplicates
// redeliveries.
func (a *Adapter) Accept(r *http.Request, body []byte, s source.Secrets) (string, string, error) {
	if !source.TokenMatches(r, s.WebhookToken) {
		return "", "", source.ErrUnauthorized
	}
	n, err := ParseNotification(body)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(body)
	return n.Group, hex.EncodeToString(sum[:]), nil
}

// Handle turns a stored notification, or a scheduled reconciliation, into
// an outcome.
func (a *Adapter) Handle(ctx context.Context, it store.InboxItem, env source.Env) (source.Outcome, error) {
	if it.EventType == EventReconcile {
		return a.reconcile(ctx, it, env)
	}
	n, err := ParseNotification(it.Payload)
	if err != nil {
		return source.Outcome{}, err
	}
	switch n.Group {
	case GroupNewVulnerability, GroupNewVulnerableDependency:
		sightings, err := n.Sightings()
		if err != nil {
			return source.Outcome{}, err
		}
		var out source.Outcome
		seen := map[string]bool{}
		for _, s := range sightings {
			if !seen[s.Project.UUID] {
				out.Projects = append(out.Projects, project(s.Project, nil, env))
				seen[s.Project.UUID] = true
			}
			out.Sightings = append(out.Sightings, sighting(s, it, n.Group, nil, env))
		}
		return out, nil

	case GroupBOMProcessed:
		p, err := n.SubjectProject()
		if err != nil {
			return source.Outcome{}, err
		}
		bom := n.SubjectBOM()
		out := source.Outcome{Projects: []source.Project{project(p, &bom, env)}}
		if a.Client == nil {
			a.logger().Warn("BOM_PROCESSED received but the Dependency-Track API is not configured; findings were not reconciled",
				"project", p.Name, "version", p.Version)
			out.Note = "skipped: Dependency-Track API not configured"
			return out, nil
		}
		payload, err := json.Marshal(reconcileRequest{Project: p, BOM: bom, InboxID: it.ID, NotifiedAt: n.Timestamp})
		if err != nil {
			return source.Outcome{}, err
		}
		delay := a.ReconcileDelay
		if delay == 0 {
			delay = 2 * time.Minute
		}
		due := env.Now().Add(delay)
		out.Later = []source.Followup{{EventType: EventReconcile, DedupKey: fmt.Sprintf("reconcile:%d", it.ID), Payload: payload, At: due}}
		a.logger().Info("dependency-track BOM processed; reconciliation scheduled", "id", it.ID,
			"project", p.Name, "version", p.Version, "commit", bom.Commit, "due", due.Format(time.RFC3339))
		return out, nil

	case GroupProjectAuditChange:
		ac, err := n.AuditChange()
		if err != nil {
			return source.Outcome{}, err
		}
		to, ok := ac.Analysis.FindingState()
		if !ok {
			return source.Outcome{Note: "ignored: analysis state " + ac.Analysis.State}, nil
		}
		return source.Outcome{StateChanges: []source.StateChange{{
			Ref: finding.Ref{Source: Name, Project: ac.Analysis.Project, Component: ac.Analysis.Component, Vuln: ac.Analysis.Vulnerability},
			To:  to,
			Evidence: map[string]any{
				"source":             Name,
				"notification_group": n.Group,
				"inbox_id":           it.ID,
				"analysis_state":     ac.Analysis.State,
				"suppressed":         ac.Analysis.Suppressed,
				"title":              n.Title,
			},
		}}}, nil
	}
	return source.Outcome{Note: "ignored: group " + n.Group}, nil
}

// reconcileRequest is the payload of a scheduled reconciliation.
type reconcileRequest struct {
	Project    Project `json:"project"`
	BOM        BOMInfo `json:"bom"`
	InboxID    int64   `json:"bom_processed_inbox_id"`
	NotifiedAt string  `json:"notified_at,omitempty"`
}

// reconcile reads the project's current findings: they are its complete
// snapshot, so the project's other findings are resolved.
func (a *Adapter) reconcile(ctx context.Context, it store.InboxItem, env source.Env) (source.Outcome, error) {
	var req reconcileRequest
	if err := json.Unmarshal(it.Payload, &req); err != nil {
		return source.Outcome{}, fmt.Errorf("decode reconcile request: %w", err)
	}
	if a.Client == nil {
		return source.Outcome{Note: "skipped: Dependency-Track API not configured"}, nil
	}
	sightings, err := a.Client.ProjectSightings(ctx, req.Project)
	if err != nil {
		return source.Outcome{}, err
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
	evidence := map[string]any{
		"source":                 Name,
		"dt_project":             req.Project,
		"bom_processed_inbox_id": req.InboxID,
		"bom_processed_at":       req.NotifiedAt,
	}
	for k, v := range bomEvidence {
		evidence[k] = v
	}
	out := source.Outcome{Snapshot: &source.Snapshot{Source: Name, Project: req.Project.UUID, Evidence: evidence}}
	for _, s := range sightings {
		out.Sightings = append(out.Sightings, sighting(s, it, GroupBOMProcessed, bomEvidence, env))
	}
	return out, nil
}

func project(p Project, bom *BOMInfo, env source.Env) source.Project {
	service, _, registered := env.Resolve(p.Name)
	sp := store.SourceProject{Source: Name, ProjectID: p.UUID, Name: p.Name, Version: p.Version,
		Service: service, Registered: registered}
	if bom != nil {
		sp.Commit, sp.Ref, sp.BOMSerial = bom.Commit, bom.Ref, bom.Serial
	}
	return source.Project{SourceProject: sp, BOM: bom != nil}
}

func sighting(s Sighting, it store.InboxItem, group string, extra map[string]any, env source.Env) source.Sighting {
	evidence := map[string]any{
		"source":             Name,
		"notification_group": group,
		"inbox_id":           it.ID,
		"dt_project":         s.Project,
		"dt_vuln_id":         s.Vulnerability.VulnID,
	}
	for k, v := range extra {
		evidence[k] = v
	}
	return source.Sighting{Observation: observe(s, env), Evidence: evidence}
}

func observe(s Sighting, env source.Env) finding.Observation {
	service, repo, registered := env.Resolve(s.Project.Name)
	environment := s.Project.Version
	if environment == "" {
		environment = finding.DefaultEnvironment
	}
	id, aliases := finding.CanonicalID(s.Vulnerability.VulnID, s.Vulnerability.Aliases)
	ref := finding.Ref{Source: Name, Project: s.Project.UUID, Component: s.Component.UUID, Vuln: s.Vulnerability.UUID,
		VulnSource: s.Vulnerability.Source, VulnName: s.Vulnerability.VulnID}
	return finding.Observation{
		Service:          service,
		Registered:       registered,
		Repository:       repo,
		Environment:      environment,
		ComponentRef:     s.Component.Ref(),
		ComponentName:    s.Component.DisplayName(),
		ComponentVersion: s.Component.Version,
		VulnID:           id,
		Aliases:          aliases,
		Severity:         finding.NormalizeSeverity(s.Vulnerability.Severity),
		Title:            s.Vulnerability.Title,
		Ref:              ref,
		// Still written to findings.dt_* until those columns are dropped.
		DTProjectUUID:       s.Project.UUID,
		DTComponentUUID:     s.Component.UUID,
		DTVulnerabilityUUID: s.Vulnerability.UUID,
		DTVulnSource:        s.Vulnerability.Source,
		DTVulnID:            s.Vulnerability.VulnID,
		EPSS:                s.Vulnerability.EPSSScore,
	}
}
