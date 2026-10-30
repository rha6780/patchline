// Package vex exports the state of a project version's vulnerabilities as
// a CycloneDX 1.5 VEX document, so scanners and customers can tell which
// reported vulnerabilities are not exploitable, accepted, or being fixed.
package vex

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rha6780/patchline/internal/finding"
	"github.com/rha6780/patchline/internal/store"
)

// Document is a CycloneDX VEX document.
type Document struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber"`
	Version         int             `json:"version"`
	Metadata        metadata        `json:"metadata"`
	Components      []component     `json:"components"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type metadata struct {
	Timestamp string `json:"timestamp"`
	Tools     struct {
		Components []component `json:"components"`
	} `json:"tools"`
	Component component `json:"component"`
}

type component struct {
	BOMRef  string `json:"bom-ref,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type vulnerability struct {
	BOMRef      string      `json:"bom-ref"`
	ID          string      `json:"id"`
	Source      *source     `json:"source,omitempty"`
	References  []reference `json:"references,omitempty"`
	Ratings     []rating    `json:"ratings,omitempty"`
	Description string      `json:"description,omitempty"`
	Analysis    analysis    `json:"analysis"`
	Affects     []affect    `json:"affects"`
}

type source struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type reference struct {
	ID     string `json:"id"`
	Source source `json:"source"`
}

type rating struct {
	Severity string `json:"severity"`
	Method   string `json:"method"`
}

type analysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	LastUpdated   string   `json:"lastUpdated,omitempty"`
}

type affect struct {
	Ref string `json:"ref"`
}

// Build describes the findings of one project version. Findings are the
// ones the project currently reports (open and closed); the components
// are the snapshot's.
func Build(p store.SourceProject, findings []store.Finding, components []store.Component, tool string, now time.Time) Document {
	doc := Document{BOMFormat: "CycloneDX", SpecVersion: "1.5", SerialNumber: "urn:uuid:" + uuid(), Version: 1,
		Components: []component{}, Vulnerabilities: []vulnerability{}}
	doc.Metadata.Timestamp = now.UTC().Format(time.RFC3339)
	doc.Metadata.Tools.Components = []component{{Type: "application", Name: "Patchline", Version: tool}}
	doc.Metadata.Component = component{Type: "application", Name: p.Name, Version: p.Version}

	names := map[string]store.Component{}
	for _, c := range components {
		names[c.PURL] = c
	}
	used := map[string]bool{}
	for _, f := range findings {
		ref := f.ComponentRef
		if !used[ref] {
			used[ref] = true
			c := component{BOMRef: ref, Type: "library", Name: f.ComponentName, Version: f.ComponentVersion}
			if strings.HasPrefix(ref, "pkg:") {
				c.PURL = ref
			}
			if sc, ok := names[ref]; ok && c.Name == "" {
				c.Name = sc.Name
			}
			if c.Name == "" {
				c.Name = ref
			}
			doc.Components = append(doc.Components, c)
		}
		v := vulnerability{
			BOMRef: fmt.Sprintf("%s#%s", f.VulnID, ref), ID: f.VulnID, Source: sourceOf(f.VulnID),
			Description: f.Title, Analysis: analysisOf(f), Affects: []affect{{Ref: ref}},
		}
		if sev := f.DisplaySeverity(); sev != "" && sev != finding.SeverityUnassigned {
			v.Ratings = []rating{{Severity: sev, Method: "other"}}
		}
		for _, a := range f.Aliases {
			if s := sourceOf(a); s != nil {
				v.References = append(v.References, reference{ID: a, Source: *s})
			}
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)
	}
	sort.Slice(doc.Components, func(i, j int) bool { return doc.Components[i].BOMRef < doc.Components[j].BOMRef })
	return doc
}

// analysisOf maps a finding to a CycloneDX analysis.
func analysisOf(f store.Finding) analysis {
	a := analysis{LastUpdated: rfc3339(f.UpdatedAt)}
	switch finding.State(f.State) {
	case finding.StateNotAffected:
		a.State = store.AnalysisNotAffected
		if f.Analysis != nil && f.Analysis.State == store.AnalysisFalsePositive {
			a.State = store.AnalysisFalsePositive
		}
	case finding.StateRiskAccepted:
		a.State, a.Response = store.AnalysisExploitable, []string{store.ResponseWillNotFix}
	case finding.StateAwaitingVerification:
		// A fix is merged; the next SBOM confirms it.
		a.State, a.Response = "in_triage", []string{"update"}
	case finding.StateResolved:
		a.State = "resolved"
	default:
		a.State = "in_triage"
	}
	if f.Analysis != nil && !finding.State(f.State).Open() {
		a.Justification, a.Detail = f.Analysis.Justification, f.Analysis.Detail
		if f.Analysis.At != "" {
			a.LastUpdated = rfc3339(f.Analysis.At)
		}
	}
	return a
}

func sourceOf(id string) *source {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return &source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + id}
	case strings.HasPrefix(id, "GHSA-"):
		return &source{Name: "GitHub", URL: "https://github.com/advisories/" + id}
	case id != "":
		return &source{Name: "OSV", URL: "https://osv.dev/vulnerability/" + id}
	}
	return nil
}

func rfc3339(stored string) string {
	t, err := time.Parse(store.TimeLayout, stored)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
