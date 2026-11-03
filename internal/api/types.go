package api

import (
	"encoding/json"

	"github.com/rha6780/patchline/internal/impact"
	"github.com/rha6780/patchline/internal/inventory"
	"github.com/rha6780/patchline/internal/store"
)

// The response types below are the API's contract, described in
// openapi.yaml. They are copied from the store types on purpose, so a
// change to the database does not change the API by accident.

// Finding is a finding with its service's inventory context.
type Finding struct {
	ID                int64     `json:"id"`
	Service           string    `json:"service"`
	Registered        bool      `json:"registered"`
	Repository        string    `json:"repository"`
	Environment       string    `json:"environment"`
	ComponentRef      string    `json:"component_ref"`
	ComponentName     string    `json:"component_name"`
	ComponentVersion  string    `json:"component_version"`
	VulnID            string    `json:"vuln_id"`
	Aliases           []string  `json:"aliases"`
	Title             string    `json:"title,omitempty"`
	Severity          string    `json:"severity"`
	EffectiveSeverity string    `json:"effective_severity,omitempty"`
	SLAReasons        []string  `json:"sla_reasons,omitempty"`
	EPSS              *float64  `json:"epss,omitempty"`
	KEV               bool      `json:"kev"`
	State             string    `json:"state"`
	DueAt             *string   `json:"due_at,omitempty"`
	DueOverride       *string   `json:"due_override,omitempty"`
	SLAStartedAt      *string   `json:"sla_started_at,omitempty"`
	FirstSeenAt       string    `json:"first_seen_at"`
	ResolvedAt        *string   `json:"resolved_at,omitempty"`
	UpdatedAt         string    `json:"updated_at"`
	Assignee          string    `json:"assignee,omitempty"`
	Analysis          *Analysis `json:"analysis,omitempty"`
	DTProjectUUID     string    `json:"dt_project_uuid,omitempty"`
	DTVulnSource      string    `json:"dt_vuln_source,omitempty"`
	DTVulnID          string    `json:"dt_vuln_id,omitempty"`

	// From the inventory.
	Owners       []string `json:"owners"`
	SlackChannel string   `json:"slack_channel,omitempty"`
	Exposure     string   `json:"exposure,omitempty"`
}

// Analysis is the approved decision behind a closed finding.
type Analysis struct {
	State         string `json:"state"`
	Justification string `json:"justification,omitempty"`
	Response      string `json:"response,omitempty"`
	Detail        string `json:"detail,omitempty"`
	By            string `json:"by,omitempty"`
	At            string `json:"at,omitempty"`
}

// Event is an entry of a finding's timeline.
type Event struct {
	ID         int64           `json:"id"`
	Kind       string          `json:"kind"`
	FromState  *string         `json:"from_state,omitempty"`
	ToState    *string         `json:"to_state,omitempty"`
	Evidence   json.RawMessage `json:"evidence"`
	OccurredAt string          `json:"occurred_at"`
}

// PullRequest is a fix pull request linked to a finding.
type PullRequest struct {
	FindingID     int64  `json:"finding_id"`
	Repository    string `json:"repository"`
	Number        int    `json:"number"`
	URL           string `json:"url"`
	Title         string `json:"title"`
	State         string `json:"state"`
	Package       string `json:"package"`
	FromVersion   string `json:"from_version,omitempty"`
	ToVersion     string `json:"to_version"`
	Verdict       string `json:"verdict"`
	VerdictDetail string `json:"verdict_detail,omitempty"`
	HeadSHA       string `json:"head_sha,omitempty"`
	MergeSHA      string `json:"merge_sha,omitempty"`
	CreatedAt     string `json:"created_at"`
}

// ComponentUse is a component in a stored SBOM snapshot.
type ComponentUse struct {
	PURL         string `json:"purl"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Ecosystem    string `json:"ecosystem,omitempty"`
	Package      string `json:"package,omitempty"`
	Source       string `json:"source"`
	ProjectID    string `json:"project_id"`
	Project      string `json:"project"`
	Environment  string `json:"environment"`
	Service      string `json:"service"`
	Registered   bool   `json:"registered"`
	LastBOMAt    string `json:"last_bom_at,omitempty"`
	Commit       string `json:"commit,omitempty"`
	OpenFindings int    `json:"open_findings"`
}

// AffectedUse is a snapshot containing an affected version.
type AffectedUse struct {
	ComponentUse
	Advisory string   `json:"advisory"`
	Range    string   `json:"affected_range"`
	Fixed    string   `json:"fixed_version,omitempty"`
	Finding  *Finding `json:"finding,omitempty"`
}

// AffectedPackage is an affected package of a vulnerability.
type AffectedPackage struct {
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Ranges    []string `json:"ranges"`
}

// Impact is what a vulnerability affects.
type Impact struct {
	ID         string            `json:"id"`
	Aliases    []string          `json:"aliases"`
	Summary    string            `json:"summary,omitempty"`
	Severity   string            `json:"severity,omitempty"`
	Advisories []string          `json:"advisories"`
	Packages   []AffectedPackage `json:"packages"`
	Affected   []AffectedUse     `json:"affected"`
	Unaffected int               `json:"unaffected"`
	Findings   []Finding         `json:"findings"`
}

func newFinding(f store.Finding, inv *inventory.Inventory) Finding {
	out := Finding{
		ID: f.ID, Service: f.Service, Registered: f.Registered, Repository: f.Repository, Environment: f.Environment,
		ComponentRef: f.ComponentRef, ComponentName: f.ComponentName, ComponentVersion: f.ComponentVersion,
		VulnID: f.VulnID, Aliases: nonNil(f.Aliases), Title: f.Title, Severity: f.Severity,
		EffectiveSeverity: f.EffectiveSeverity, SLAReasons: f.SLAReasons, EPSS: f.EPSS, KEV: f.KEV, State: f.State,
		DueAt: f.DueAt, DueOverride: f.DueOverride, SLAStartedAt: f.SLAStartedAt, FirstSeenAt: f.FirstSeenAt,
		ResolvedAt: f.ResolvedAt, UpdatedAt: f.UpdatedAt, Assignee: f.Assignee,
		DTProjectUUID: f.DTProjectUUID, DTVulnSource: f.DTVulnSource, DTVulnID: f.DTVulnID,
		Owners: []string{},
	}
	if a := f.Analysis; a != nil {
		out.Analysis = &Analysis{State: a.State, Justification: a.Justification, Response: a.Response,
			Detail: a.Detail, By: a.By, At: a.At}
	}
	if f.Registered {
		if s, ok := inv.Service(f.Service); ok {
			out.Owners = append(out.Owners, s.Owners...)
			out.SlackChannel = s.SlackChannel
			out.Exposure = string(s.Exposure)
		}
	}
	return out
}

func newFindings(list []store.Finding, inv *inventory.Inventory) []Finding {
	out := make([]Finding, 0, len(list))
	for _, f := range list {
		out = append(out, newFinding(f, inv))
	}
	return out
}

func newEvents(list []store.FindingEvent) []Event {
	out := make([]Event, 0, len(list))
	for _, e := range list {
		ev := e.Evidence
		if len(ev) == 0 {
			ev = json.RawMessage("{}")
		}
		out = append(out, Event{ID: e.ID, Kind: e.Kind, FromState: e.FromState, ToState: e.ToState,
			Evidence: ev, OccurredAt: e.OccurredAt})
	}
	return out
}

func newPullRequests(list []store.PullRequestLink) []PullRequest {
	out := make([]PullRequest, 0, len(list))
	for _, p := range list {
		out = append(out, PullRequest{FindingID: p.FindingID, Repository: p.Repository, Number: p.Number, URL: p.URL,
			Title: p.Title, State: p.State, Package: p.Package, FromVersion: p.FromVersion, ToVersion: p.ToVersion,
			Verdict: p.Verdict, VerdictDetail: p.VerdictDetail, HeadSHA: p.HeadSHA, MergeSHA: p.MergeSHA, CreatedAt: p.CreatedAt})
	}
	return out
}

func newComponentUse(u store.ComponentUse) ComponentUse {
	return ComponentUse{PURL: u.PURL, Name: u.Name, Version: u.Version, Ecosystem: u.Ecosystem, Package: u.Package,
		Source: u.Source, ProjectID: u.ProjectID, Project: u.Project, Environment: u.Environment, Service: u.Service,
		Registered: u.Registered, LastBOMAt: u.LastBOMAt, Commit: u.Commit, OpenFindings: u.OpenFindings}
}

func newComponentUses(list []store.ComponentUse) []ComponentUse {
	out := make([]ComponentUse, 0, len(list))
	for _, u := range list {
		out = append(out, newComponentUse(u))
	}
	return out
}

func newImpact(r impact.Report, inv *inventory.Inventory) Impact {
	out := Impact{ID: r.ID, Aliases: nonNil(r.Aliases), Summary: r.Summary, Severity: r.Severity,
		Advisories: nonNil(r.Advisories), Packages: []AffectedPackage{}, Affected: []AffectedUse{},
		Unaffected: r.Unaffected, Findings: newFindings(r.Findings, inv)}
	for _, p := range r.Packages {
		out.Packages = append(out.Packages, AffectedPackage{Ecosystem: p.Ecosystem, Package: p.Package, Ranges: nonNil(p.Ranges)})
	}
	for _, u := range r.Affected {
		a := AffectedUse{ComponentUse: newComponentUse(u.ComponentUse), Advisory: u.Advisory, Range: u.Range, Fixed: u.Fixed}
		if u.Finding != nil {
			f := newFinding(*u.Finding, inv)
			a.Finding = &f
		}
		out.Affected = append(out.Affected, a)
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
