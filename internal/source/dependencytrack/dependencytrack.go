package dependencytrack

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/rha6780/patchline/internal/finding"
)

// Notification groups Patchline acts on. Others are accepted and ignored.
const (
	GroupNewVulnerability        = "NEW_VULNERABILITY"
	GroupNewVulnerableDependency = "NEW_VULNERABLE_DEPENDENCY"
	GroupBOMProcessed            = "BOM_PROCESSED"
	GroupProjectAuditChange      = "PROJECT_AUDIT_CHANGE"
)

// Project identifies a Dependency-Track project. Patchline treats Name as
// the inventory key and Version as the environment.
type Project struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component is a package inside a project.
type Component struct {
	UUID    string `json:"uuid"`
	Group   string `json:"group"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	CPE     string `json:"cpe"`
	Project string `json:"project"` // project uuid (finding API only)
}

// Ref returns the best stable identifier for the component.
func (c Component) Ref() string {
	switch {
	case c.PURL != "":
		return c.PURL
	case c.CPE != "":
		return c.CPE
	}
	name := c.Name
	if c.Group != "" {
		name = c.Group + "/" + c.Name
	}
	return "dependency-track:" + name + "@" + c.Version
}

// DisplayName returns group/name, or name when there is no group.
func (c Component) DisplayName() string {
	if c.Group != "" {
		return c.Group + "/" + c.Name
	}
	return c.Name
}

// Vulnerability is a vulnerability as Dependency-Track reports it.
type Vulnerability struct {
	UUID     string  `json:"uuid"`
	VulnID   string  `json:"vulnId"`
	Source   string  `json:"source"`
	Title    string  `json:"title"`
	Severity string  `json:"severity"`
	Aliases  Aliases `json:"aliases"`
}

// Aliases accepts both alias shapes Dependency-Track emits:
// notifications use [{"vulnId": "GHSA-..", "source": "GITHUB"}], while the
// finding API uses [{"cveId": "CVE-..", "ghsaId": "GHSA-.."}].
type Aliases []string

func (a *Aliases) UnmarshalJSON(data []byte) error {
	var raw []map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	var ids []string
	for _, m := range raw {
		if v, ok := m["vulnId"].(string); ok {
			ids = append(ids, v)
			continue
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if v, ok := m[k].(string); ok {
				ids = append(ids, v)
			}
		}
	}
	*a = ids
	return nil
}

// Sighting is one (project, component, vulnerability) triple, the common
// shape extracted from notifications and from the finding API.
type Sighting struct {
	Project       Project
	Component     Component
	Vulnerability Vulnerability
}

// Notification is the outbound webhook payload.
type Notification struct {
	Level     string          `json:"level"`
	Scope     string          `json:"scope"`
	Group     string          `json:"group"`
	Timestamp string          `json:"timestamp"`
	Title     string          `json:"title"`
	Content   string          `json:"content"`
	Subject   json.RawMessage `json:"subject"`
}

// ParseNotification decodes a webhook body.
func ParseNotification(body []byte) (Notification, error) {
	var env struct {
		Notification Notification `json:"notification"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return Notification{}, fmt.Errorf("decode notification: %w", err)
	}
	if env.Notification.Group == "" {
		return Notification{}, fmt.Errorf("decode notification: missing notification.group")
	}
	return env.Notification, nil
}

// Sightings extracts the vulnerability sightings carried by
// NEW_VULNERABILITY and NEW_VULNERABLE_DEPENDENCY notifications. Other
// groups return nil.
func (n Notification) Sightings() ([]Sighting, error) {
	switch n.Group {
	case GroupNewVulnerability:
		var s struct {
			Component        Component     `json:"component"`
			Vulnerability    Vulnerability `json:"vulnerability"`
			AffectedProjects []Project     `json:"affectedProjects"`
		}
		if err := json.Unmarshal(n.Subject, &s); err != nil {
			return nil, fmt.Errorf("decode %s subject: %w", n.Group, err)
		}
		out := make([]Sighting, 0, len(s.AffectedProjects))
		for _, p := range s.AffectedProjects {
			out = append(out, Sighting{Project: p, Component: s.Component, Vulnerability: s.Vulnerability})
		}
		return out, nil

	case GroupNewVulnerableDependency:
		var s struct {
			Project         Project         `json:"project"`
			Component       Component       `json:"component"`
			Vulnerabilities []Vulnerability `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(n.Subject, &s); err != nil {
			return nil, fmt.Errorf("decode %s subject: %w", n.Group, err)
		}
		out := make([]Sighting, 0, len(s.Vulnerabilities))
		for _, v := range s.Vulnerabilities {
			out = append(out, Sighting{Project: s.Project, Component: s.Component, Vulnerability: v})
		}
		return out, nil
	}
	return nil, nil
}

// SubjectProject returns the project of BOM_CONSUMED / BOM_PROCESSED and
// NEW_VULNERABLE_DEPENDENCY notifications.
func (n Notification) SubjectProject() (Project, error) {
	var s struct {
		Project Project `json:"project"`
	}
	if err := json.Unmarshal(n.Subject, &s); err != nil {
		return Project{}, fmt.Errorf("decode %s subject: %w", n.Group, err)
	}
	if s.Project.UUID == "" {
		return Project{}, fmt.Errorf("%s: subject has no project uuid", n.Group)
	}
	return s.Project, nil
}

// Analysis is a Dependency-Track audit decision on one finding.
type Analysis struct {
	State         string `json:"state"`
	Suppressed    bool   `json:"suppressed"`
	Project       string `json:"project"`       // project uuid
	Component     string `json:"component"`     // component uuid
	Vulnerability string `json:"vulnerability"` // vulnerability uuid
}

// FindingState maps the decision to a Patchline state. Suppressing a
// finding that is not marked not-affected is treated as risk acceptance.
func (a Analysis) FindingState() (finding.State, bool) {
	switch a.State {
	case "NOT_AFFECTED", "FALSE_POSITIVE":
		return finding.StateNotAffected, true
	}
	if a.Suppressed {
		return finding.StateRiskAccepted, true
	}
	switch a.State {
	case "IN_TRIAGE", "EXPLOITABLE":
		return finding.StateInProgress, true
	case "RESOLVED":
		// A person says it is fixed; a rescan has to confirm it.
		return finding.StateAwaitingVerification, true
	case "NOT_SET", "":
		return finding.StateNew, true
	}
	return "", false
}

// AuditChange is the subject of PROJECT_AUDIT_CHANGE.
type AuditChange struct {
	Component        Component     `json:"component"`
	Vulnerability    Vulnerability `json:"vulnerability"`
	Analysis         Analysis      `json:"analysis"`
	AffectedProjects []Project     `json:"affectedProjects"`
}

// AuditChange decodes a PROJECT_AUDIT_CHANGE subject.
func (n Notification) AuditChange() (AuditChange, error) {
	var a AuditChange
	if err := json.Unmarshal(n.Subject, &a); err != nil {
		return AuditChange{}, fmt.Errorf("decode %s subject: %w", n.Group, err)
	}
	if a.Analysis.Component == "" {
		a.Analysis.Component = a.Component.UUID
	}
	if a.Analysis.Vulnerability == "" {
		a.Analysis.Vulnerability = a.Vulnerability.UUID
	}
	if a.Analysis.Project == "" && len(a.AffectedProjects) == 1 {
		a.Analysis.Project = a.AffectedProjects[0].UUID
	}
	if a.Analysis.Project == "" || a.Analysis.Component == "" || a.Analysis.Vulnerability == "" {
		return AuditChange{}, fmt.Errorf("%s: analysis is missing project, component or vulnerability uuid", n.Group)
	}
	return a, nil
}
