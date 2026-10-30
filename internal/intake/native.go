package intake

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/sbom"
	"github.com/rha6780/patchline/internal/source/osv"
	"github.com/rha6780/patchline/internal/store"
)

// SourcePatchline is the inbox source of SBOMs uploaded to Patchline and of
// re-analyses after the vulnerability data changed.
const SourcePatchline = finding.SourcePatchline

// Inbox event types of the Patchline source.
const (
	EventSBOM      = "sbom"
	EventReanalyze = "reanalyze"
)

// Matcher detects vulnerabilities in components.
type Matcher interface {
	// Ready reports whether the vulnerability data is complete enough that
	// a component without matches can count as fixed.
	Ready(ctx context.Context) (bool, error)
	Match(ctx context.Context, c store.Component) ([]osv.Match, error)
}

func (p *Processor) handlePatchline(ctx context.Context, it store.InboxItem) (string, error) {
	switch it.EventType {
	case EventSBOM:
		return p.handleSBOM(ctx, it)
	case EventReanalyze:
		return p.reanalyze(ctx, it)
	}
	return "ignored event " + it.EventType, nil
}

// handleSBOM stores an uploaded SBOM's components as the project's snapshot
// and analyzes them.
func (p *Processor) handleSBOM(ctx context.Context, it store.InboxItem) (string, error) {
	var up sbom.Upload
	if err := json.Unmarshal(it.Payload, &up); err != nil {
		return "", fmt.Errorf("decode upload: %w", err)
	}
	doc, err := sbom.Parse(up.BOM)
	if err != nil {
		return "", err
	}
	id := sbom.ProjectID(up.Project, up.Version)
	comps := make([]store.Component, 0, len(doc.Components))
	for _, c := range doc.Components {
		comps = append(comps, store.Component{PURL: c.PURL, Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem, Package: c.Package})
	}
	if err := p.Store.ReplaceComponents(ctx, SourcePatchline, id, comps); err != nil {
		return "", err
	}
	service, _, registered := p.lookup(up.Project)
	sp := store.SourceProject{Source: SourcePatchline, ProjectID: id, Name: up.Project, Version: up.Version,
		Service: service, Registered: registered, Commit: doc.Commit, Ref: doc.Ref, BOMSerial: doc.Serial}
	if err := p.Store.TouchSourceProject(ctx, sp, true); err != nil {
		return "", err
	}
	evidence := map[string]any{"source": SourcePatchline, "project": up.Project, "version": up.Version,
		"inbox_id": it.ID, "sbom_format": doc.Format}
	if doc.Commit != "" {
		evidence["commit"] = doc.Commit
	}
	if doc.Ref != "" {
		evidence["ref"] = doc.Ref
	}
	if doc.Serial != "" {
		evidence["bom_serial"] = doc.Serial
	}
	note, err := p.analyze(ctx, sp, comps, evidence)
	if err != nil {
		return "", err
	}
	p.Logger.Info("sbom analyzed", "id", it.ID, "project", up.Project, "version", up.Version, "format", doc.Format,
		"components", len(comps), "without_purl", doc.WithoutPURL, "result", note)
	return note, nil
}

// reanalyze matches every stored snapshot again, after the vulnerability
// data changed: new advisories create findings for code that did not
// change, withdrawn ones resolve theirs.
func (p *Processor) reanalyze(ctx context.Context, it store.InboxItem) (string, error) {
	projects, err := p.Store.SourceProjects(ctx, SourcePatchline)
	if err != nil {
		return "", err
	}
	for _, sp := range projects {
		comps, err := p.Store.Components(ctx, SourcePatchline, sp.ProjectID)
		if err != nil {
			return "", err
		}
		// The inventory may have changed since the upload.
		sp.Service, _, sp.Registered = p.lookup(sp.Name)
		evidence := map[string]any{"source": SourcePatchline, "project": sp.Name, "version": sp.Version,
			"inbox_id": it.ID, "reanalysis": true}
		if sp.Commit != "" {
			evidence["commit"] = sp.Commit
		}
		if sp.Ref != "" {
			evidence["ref"] = sp.Ref
		}
		if _, err := p.analyze(ctx, sp, comps, evidence); err != nil {
			return "", fmt.Errorf("%s@%s: %w", sp.Name, sp.Version, err)
		}
	}
	p.Logger.Info("sboms re-analyzed", "projects", len(projects))
	return fmt.Sprintf("re-analyzed %d projects", len(projects)), nil
}

// analyze matches a snapshot, records its findings and resolves those the
// snapshot no longer contains.
func (p *Processor) analyze(ctx context.Context, sp store.SourceProject, comps []store.Component, evidence map[string]any) (string, error) {
	if p.Matcher == nil {
		return "stored; matching is off", nil
	}
	env := sp.Version
	if env == "" {
		env = DefaultEnvironment
	}
	_, repo, _ := p.lookup(sp.Name)
	var ids []int64
	created := 0
	for _, c := range comps {
		matches, err := p.Matcher.Match(ctx, c)
		if err != nil {
			return "", err
		}
		for _, m := range matches {
			id, aliases := finding.CanonicalID(m.ID, m.Aliases)
			obs := finding.Observation{
				Service: sp.Service, Registered: sp.Registered, Repository: repo, Environment: env,
				ComponentRef: c.PURL, ComponentName: c.Name, ComponentVersion: c.Version,
				VulnID: id, Aliases: aliases, Severity: m.Severity, Title: m.Summary,
				Source: SourcePatchline, SourceProject: sp.ProjectID,
			}
			ev := map[string]any{"osv_id": m.ID, "affected_range": m.Range}
			if m.Fixed != "" {
				ev["fixed_version"] = m.Fixed
			}
			for k, v := range evidence {
				ev[k] = v
			}
			fid, isNew, err := p.Store.UpsertFinding(ctx, obs, ev)
			if err != nil {
				return "", fmt.Errorf("upsert %s %s: %w", c.PURL, id, err)
			}
			ids = append(ids, fid)
			if isNew {
				created++
				p.Logger.Info("new finding", "service", obs.Service, "environment", env, "component", c.PURL,
					"vuln", id, "severity", obs.Severity, "source", SourcePatchline)
			}
		}
	}
	ready, err := p.Matcher.Ready(ctx)
	if err != nil {
		return "", err
	}
	resolved := 0
	if ready {
		r, err := p.Store.ResolveMissingIn(ctx, SourcePatchline, sp.ProjectID, ids, evidence)
		if err != nil {
			return "", err
		}
		resolved = len(r)
	}
	if created > 0 || resolved > 0 || len(ids) > 0 {
		p.OnChange()
	}
	note := fmt.Sprintf("%d findings (%d new), %d resolved", len(ids), created, resolved)
	if !ready {
		note += "; vulnerability data still syncing, nothing resolved"
	}
	return note, nil
}

// lookup maps a project name to a service through the inventory.
func (p *Processor) lookup(project string) (service, repo string, registered bool) {
	if m, ok := p.Inventory.LookupProject(project); ok {
		return m.Service.Name, m.Repository, true
	}
	return project, "", false
}
